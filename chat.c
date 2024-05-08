#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <stdio.h>
#include "dh.h"
#include "keys.h"
#include "prf.h"
#include "rsa.h"
#include "hmac.h"
#include "protocol.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifdef __APPLE__
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#define NEWZ(x) \
	mpz_t x;    \
	mpz_init(x)
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, &len, -1, 1, 0, 0, x)

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;	/* view for transcript */
static GtkTextMark *mark;	/* used for scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messagess and post to queue */
void *recvMsg(void *);	/* for trecv */

#define max(a, b) \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n", port);
	listen(listensock, 1);
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char *hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL)
	{
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd, 2);
	unsigned char dummy[64];
	ssize_t r;
	do
	{
		r = recv(sockfd, dummy, 64, 0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char *message, char **tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf, &t0);
	size_t len = g_utf8_strlen(message, -1);
	if (ensurenewline && message[len - 1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf, &t0, message, len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf, &t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0, len);
	if (tagnames)
	{
		char **tag = tagnames;
		while (*tag)
		{
			gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
			tag++;
		}
	}
	if (!ensurenewline)
		return;
	gtk_text_buffer_add_mark(tbuf, mark, &t1);
	gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tbuf, mark);
}

static void sendMessage(GtkWidget *w /* <-- msg entry widget */, gpointer /* data */)
{
	char *tags[2] = {"self", NULL};
	tsappend("me: ", tags, 0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;	/* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
	size_t len = g_utf8_strlen(message, -1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd, message, len, 0)) == -1)
		error("send failed");

	tsappend(message, NULL, 1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char *tags[2] = {"friend", NULL};
	char *friendname = "mr. friend: ";
	tsappend(friendname, tags, 0);
	char *message = (char *)msg;
	tsappend(message, NULL, 1);
	free(message);
	return 0;
}

/**********************************FOR PRINTING**********************************************************************/
void print_key(char *message, mpz_t key)
{
	char *key_str = mpz_get_str(NULL, 16, key);
	printf("%s%.16s\n", message, key_str);
	free(key_str);
}
/**********************************************************************************************************************/

int main(int argc, char *argv[])
{
	if (init("params") != 0)
	{
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
	{
		switch (c)
		{
		case 'c':
			if (strnlen(optarg, HOST_NAME_MAX))
				strncpy(hostname, optarg, HOST_NAME_MAX);
			break;
		case 'l':
			isclient = 0;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(usage, argv[0]);
			return 0;
		case '?':
			printf(usage, argv[0]);
			return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */

	/* Diffie Hellman key exchange + HKDF ********************************************************************************/
	if (isclient)
	{
		printf("-------- CLIENT --------\n");
		initClientNet(hostname, port);

		// Generate client key pair
		NEWZ(client_sk);
		NEWZ(client_pk);
		dhGen(client_sk, client_pk);
		print_key("Client-- Client public key: ", client_pk);
		print_key("Client-- Client private key: ", client_sk);
		// Send client public key to server
		char *client_pk_str = mpz_get_str(NULL, 16, client_pk);
		if (send(sockfd, client_pk_str, strlen(client_pk_str) + 1, 0) == -1)
		{
			fprintf(stderr, "Client-- Failed to send public key.\n");
			return 1;
		}
		free(client_pk_str);

		// Receive server public key
		char server_pk_str[1024]; // Adjust size as per your needs
		ssize_t nbytes = recv(sockfd, server_pk_str, sizeof(server_pk_str), 0);
		if (nbytes == -1 || nbytes == 0)
		{
			fprintf(stderr, "Client-- Failed to receive data.\n");
			return 1;
		}

		// Convert server public key to mpz_t
		NEWZ(server_pk);
		int status = mpz_set_str(server_pk, server_pk_str, 16);
		if (status == -1)
		{
			fprintf(stderr, "Server-- Failed to recover data.\n");
			return 1;
		}
		print_key("Client-- Server public key recieved: ", server_pk);

		// Compute the shared secret key
		NEWZ(shared_secret);
		mpz_powm(shared_secret, server_pk, client_sk, p); // Compute g^(ab) mod p
		print_key("Client-- Shared secret: ", shared_secret);

		// Generate session token with random bytes
		NEWZ(session_id);
		unsigned char session_token[16];
		randBytes(session_token, 16);
		BYTES2Z(session_id, session_token, 16);
		print_key("Client-- Session token: ", session_id);

		// Receive hash secret from server
		unsigned char incomingkeys[48];
		nbytes = recv(sockfd, incomingkeys, 48, 0);
		if (nbytes == -1 || nbytes == 0)
		{
			fprintf(stderr, "Client-- Failed to receive data.\n");
			return 1;
		}

		// Prepare buffer for shared secret and session token
		size_t shared_secret_size = (size_t)mpz_sizeinbase(shared_secret, 256);
		unsigned char shared_buf[shared_secret_size];
		Z2BYTES(shared_buf, shared_secret_size, shared_secret);

		// Get the hmackey
		unsigned char hmackey[32];
		readHmacKey("hmac.pem", hmackey, "private.pem");

		// Break the data and verify hash
		unsigned char serverhash[32];
		memcpy(serverhash, incomingkeys, 32);
		unsigned char server_id[16];
		memcpy(server_id, incomingkeys + 32, 16);
		unsigned char hash[32]; // hash of the client
		sha256_hash(shared_buf, hash, hmackey, shared_secret_size);
		if (memcmp(hash, serverhash, 32) != 0)
		{
			fprintf(stderr, "Client-- Failed to verify hash secret.\n");
			return 1;
		}
		if (send(sockfd, session_token, 16, 0) == -1)
		{
			fprintf(stderr, "Client-- Failed to send session id.\n");
			return 1;
		}

		// Covert server id to int
		NEWZ(sid);
		BYTES2Z(sid, server_id, 16);
		print_key("Client-- Handshake completed with server ID: ", sid);

		// Cleanup
		mpz_clear(client_sk);
		mpz_clear(client_pk);
		mpz_clear(server_pk);
		mpz_clear(shared_secret);
		mpz_clear(session_id);
		mpz_clear(sid);
	}
	else
	{
		printf("-------- SERVER --------\n");
		// Initialize server network
		initServerNet(port);

		// Receive client's public key
		char client_pk_str[1024]; // Adjust size as per your needs
		ssize_t nbytes = recv(sockfd, client_pk_str, sizeof(client_pk_str), 0);
		if (nbytes == -1 || nbytes == 0)
		{
			fprintf(stderr, "Server-- Failed to receive data.\n");
			return 1;
		}

		// Convert client public key to mpz_t
		NEWZ(client_pk);
		int status = mpz_set_str(client_pk, client_pk_str, 16);
		if (status == -1)
		{
			fprintf(stderr, "Server-- Failed to recover data.\n");
			return 1;
		}
		print_key("Server-- Client public key recieved: ", client_pk);

		// Generate server's key pair
		NEWZ(server_sk);
		NEWZ(server_pk);
		dhGen(server_sk, server_pk);
		print_key("Server-- Server public key: ", server_pk);
		print_key("Server-- Server private key: ", server_sk);

		// Send server's public key to client
		char *server_pk_str = mpz_get_str(NULL, 16, server_pk);
		if (send(sockfd, server_pk_str, strlen(server_pk_str) + 1, 0) == -1)
		{
			fprintf(stderr, "Server-- Failed to send public key.\n");
			return 1;
		}
		free(server_pk_str);

		// Compute the shared secret key
		NEWZ(shared_secret);
		mpz_powm(shared_secret, client_pk, server_sk, p); // Compute g^(ab) mod p
		print_key("Server-- Shared secret: ", shared_secret);
		// Generate session token with random bytes
		NEWZ(session_id);
		unsigned char session_token[16];
		randBytes(session_token, 16);
		BYTES2Z(session_id, session_token, 16);
		print_key("Server-- Session token: ", session_id);

		// Prepare buffer for shared secret and session token
		size_t shared_secret_size = (size_t)mpz_sizeinbase(shared_secret, 256);
		unsigned char shared_buf[shared_secret_size];
		Z2BYTES(shared_buf, shared_secret_size, shared_secret);

		// Set up RSA keys and HMAC key for hashing
		generateRSAKeys("public.pem", "private.pem");
		generateHmacKey("hmac.pem", "public.pem");

		// Get the hmackey
		unsigned char hmackey[32];
		readHmacKey("hmac.pem", hmackey, "private.pem");

		// Compute the sha256-hash
		unsigned char hash[32];
		sha256_hash(shared_buf, hash, hmackey, shared_secret_size);
		unsigned char hash_with_token[48]; // 32 bytes for shared secret + 16 bytes session token
		memcpy(hash_with_token, hash, 32);
		memcpy(hash_with_token + 32, session_token, 16);

		// Send hash of secret key and session id to client
		if (send(sockfd, hash_with_token, 48, 0) == -1)
		{
			fprintf(stderr, "Server-- Failed to send hash secret with session.\n");
			return 1;
		}

		// Receive client id
		unsigned char client_id[16];
		nbytes = recv(sockfd, client_id, 16, 0);
		if (nbytes == -1 || nbytes == 0)
		{
			fprintf(stderr, "Server-- Failed to receive client id from client.\n");
			return 1;
		}

		// Covert client id to int
		NEWZ(cid);
		BYTES2Z(cid, client_id, 16);
		print_key("Server-- Handshake completed with client ID: ", cid);

		// Cleanup
		mpz_clear(server_sk);
		mpz_clear(server_pk);
		mpz_clear(client_pk);
		mpz_clear(shared_secret);
		mpz_clear(session_id);
		mpz_clear(cid);
	}
	/**********************************************************************************************************************/

	/* setup GTK... */
	GtkBuilder *builder;
	GObject *window;
	GObject *button;
	GObject *transcript;
	GObject *message;
	GError *error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();

	if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0)
	{
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark = gtk_text_mark_new(NULL, TRUE);
	window = gtk_builder_get_object(builder, "window");
	gtk_window_set_default_size(GTK_WINDOW(window), 400, 400);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider *css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css, "colors.css", NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
											  GTK_STYLE_PROVIDER(css),
											  GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
	gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
	gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv, 0, recvMsg, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void *recvMsg(void *)
{
	size_t maxlen = 512;
	char msg[maxlen + 2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1)
	{
		if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
			error("recv failed");
		if (nbytes == 0)
		{
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char *m = malloc(maxlen + 2);
		memcpy(m, msg, nbytes);
		if (m[nbytes - 1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}
