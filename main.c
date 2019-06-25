#include <errno.h>
#include <fcntl.h> 
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define msgSIZE 3000

#define VERBOSE 0
#define DAEMON 1

typedef struct SAGmsg {
	unsigned char msgRaw[msgSIZE];
	unsigned char msgDecrypted[msgSIZE];
	
	unsigned char startByte;
	unsigned char sysTitleLen;
	unsigned char* sysTitle;
	int msgLen;
	unsigned int frameCnt;
	unsigned char* data;
	unsigned char gcmTag[12];
	unsigned char iv[12];
	
	int reqMsgIdx;
	int msgIdx;
	int ready2decode;
//	int msgStartIdx;
} SAGmsg;


int set_interface_attribs (int fd, int speed, int parity) {
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0)
	{
		printf("error %d from tcgetattr", errno);
		return -1;
	}

	cfsetospeed (&tty, speed);
	cfsetispeed (&tty, speed);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
	// disable IGNBRK for mismatched speed tests; otherwise receive break
	// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // disable break processing
	tty.c_lflag = 0;                // no signaling chars, no echo,
									// no canonical processing
	tty.c_lflag = EXTPROC;			// required on raspberry to avoid bit errors

//	printf("c_lflag: 0x%X\n", tty.c_lflag);

	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);	// ignore modem controls,
										// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);	// shut off parity
	tty.c_cflag |= parity;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	if (tcsetattr (fd, TCSANOW, &tty) != 0)
	{
		printf("error %d from tcsetattr", errno);
		return -1;
	}
	return 0;
}

void set_blocking (int fd, int should_block) {
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0)
	{
		printf("error %d from tggetattr", errno);
		return;
	}

	tty.c_cc[VMIN]  = should_block ? 1 : 0;
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	if (tcsetattr (fd, TCSANOW, &tty) != 0)
		printf("error %d setting term attributes", errno);
}

/*
void aes_gcm_decrypt(SAGmsg *msg)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
	
	unsigned char *gcm_ct = msg->data; //cipher text

    printf("AES GCM Derypt:\n");
    printf("Ciphertext:\n");
//    BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
	BIO_dump_fp(stdout, gcm_ct, msg->msgLen);
    ctx */


static const unsigned char aad[] = {    0x30, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
										0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

//static const unsigned char gcm_key[] = {0x85, 0x07, 0x8D, 0x71, 0x33, 0xDE, 0x28, 0x40, 0xF9,
	//0x07, 0x58, 0x5D, 0xB7, 0xD4, 0x10, 0x7C}; //marie-therese

unsigned char gcm_key[16]; // = {0x85, 0x07, 0x8D, 0x71, 0x33, 0xDE, 0x28, 0x40, 0xF9,
unsigned char deviceID[] = "SAG1030700331578";

/*
marie-therese
SAG1030700331578
85078D7133DE2840F907585DB7D4107C

SAG1030700285615
BC1D74457B5B192D17DFF001547A911A
*/

void aes_gcm_decrypt(struct SAGmsg *msg)
{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen, rv, msgLen;
	unsigned char outbuf[1024];

	unsigned char *gcm_ct = msg->data; //cipher text
	//	unsigned char *gcm_ct = &msg->msgRaw[msg->msgStartIdx];
	msgLen = msg->msgLen;
	//	msgLen = msg->reqMsgIdx - msg->msgStartIdx;

	if(VERBOSE) {
		printf("AES GCM Decrypt:\n");
		printf("Ciphertext:\n");
	}
	//     BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
	//        BIO_dump_fp(stdout, gcm_ct, msg->msgLen);
	ctx = EVP_CIPHER_CTX_new();
	/* Select cipher */
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	/* Set IV length, omit for 96 bits */
	//     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL); //sizeof(gcm_iv), NULL);

	//	EVP_CIPHER_CTX_set_padding(ctx, 0);
	/* Specify key and IV */
	EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, msg->iv);
	/* Zero or more calls to specify any AAD */
	EVP_DecryptUpdate(ctx, NULL, &outlen, aad, 17); //sizeof(aad));

	EVP_CIPHER_CTX_set_padding(ctx, 0);
	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, msgLen);//sizeof(gcm_ct));
	/* Output decrypted block */
	// if(VERBOSE)

	memcpy(msg->msgDecrypted, &outbuf, outlen);
	msg->msgDecrypted[outlen+1] = 0;

	//	 printf("outlen: %d\n", outlen);

	/* Set expected tag value. */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 12, msg->gcmTag);
	/* Finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
	/*
	* Print out return value. If this is not successful authentication
	* failed and plaintext is not trustworthy.
	*/

	//	 EVP_CIPHER_CTX_clean(ctx);

	//	 if(VERBOSE)
	if(!rv) {
		syslog(LOG_ERR, "Tag Verify Failed! framecnt: %d\n", msg->frameCnt);
		printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
		printf("Plaintext %d:\n", rv);
		BIO_dump_fp(stdout, outbuf, msgLen);
	}
	//	ERR_print_errors_fp(stdout);
	EVP_CIPHER_CTX_free(ctx);
}

void read_config(void) {
	FILE *lf = NULL;
	char line[256];
	char tag[10], key[64];
	
	int isComment = 0;
	
	lf = fopen("/etc/smartyMeterReader.conf", "r");
	if(lf) {
		while(fgets (line , 256 , lf) != NULL ) {
			//read line by line
			if(strlen(line) == 0)
				continue;
			
			isComment = 1;
			for(int i=0; i < strlen(line); i++) {
				if(line[i] == ' ' || line[i] == '\t' || line[i] == '\n' || line[i] == '\r')
					continue;
				else if(line[i] == '#') {
					isComment = 1;
					break;
				} else {
					isComment = 0;
//					printf("%d: %d", i, line[i]);
					break;
				}
			}
			
			if(isComment) {
				printf("comment\n");
				continue;
			}

			printf("config line: %s\n", line);

			sscanf(line, "%s %s\n", tag, key);
			printf("config tag: %s\n", tag);
			printf("config key: %s\n", key);
			
			if(strcmp(tag, "GCMKey") == 0) {
				//unsigned long long int ikey = strtoul(key, NULL, 16);
				//printf("key: %d\n", ikey);
				printf("key: 0x"); //%X\n", ikey);
				for(int i=0; i < 16; i++) {
					char key_part[2];
					key_part[0] = key[2*i];
					key_part[1] = key[2*i+1];
					
					gcm_key[i] = strtoul(key_part, NULL, 16);
					//ikey >>= 8;
					printf("%02X ", gcm_key[i]);
				}
				printf("\n");
			} else if(strcmp(tag, "DeviceID") == 0) {
				if(strlen(key) < strlen(deviceID)) {
				   printf("error reading device id");
				} else {
				   memcpy(deviceID, key, strlen(deviceID));
				}
			}
		}
		
		fclose(lf);
	} else {
		syslog(LOG_WARNING, "Could not open config file /etc/smartyMeterReader.conf!\n");
	}
}

void initMsg(SAGmsg *msg) {
	msg->startByte = 0;
	msg->sysTitleLen = 0;
	msg->sysTitle = NULL;
	msg->msgLen = 0;
	msg->frameCnt = 0;
	msg->data = NULL;
	msg->reqMsgIdx = 1; //wait for start byte
	msg->msgIdx = 0;
	msg->ready2decode = 0;
	//	msg.msgStartIdx = 0;
}

int main(int argc, char* argv[]) {
	char *portname = "/dev/ttyAMA0";
	char filename[128];
	
	//http://www.weigu.lu/microcontroller/smartyreader/index.html
	FILE *outfile, *fp = NULL;
	
	pid_t process_id = 0;
	pid_t sid = 0;
	// Create child process
	if(DAEMON) {
	   process_id = fork();
	}
	// Indication of fork() failure
	if (process_id < 0)
	{
		printf("fork failed!\n");
		// Return failure in exit status
		exit(1);
	}

	// PARENT PROCESS. Need to kill it.
	if (process_id > 0)
	{
		printf(" process_id of child process %d \n", process_id);
		
		//write to pid file
		fp = fopen("/var/run/smartyMeterReader.pid", "w");
		if(fp) {
			char buf[64];
			int n = sprintf(buf, "%d", process_id);
			fwrite(buf, 1, n, fp);
		}
		
		// return success in exit status
		exit(0);
	}
	
	if(DAEMON) {
		umask(0);
		//set new session
		sid = setsid();
	}
	if(sid < 0)
	{
		// Return failure
		exit(1);
	}
	   
	if(DAEMON) {
		// Change the current working directory to root.
		chdir("/");
		// Close stdin. stdout and stderr
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		
		stdout = fopen ("/var/log/smartyMeterReader", "a");
		setbuf(stdout,NULL);

	}
	
	int fd = open(portname, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd < 0)
	{
	        printf("error %d opening %s: %s", errno, portname, strerror (errno));
	        return 0;
	}

	set_interface_attribs (fd, B115200, 0);  // set speed to 115,200 bps, 8n1 (no parity)
	set_blocking (fd, 0);                // set no blocking

//	write (fd, "hello!\n", 7);           // send 7 character greeting

//	usleep ((7 + 25) * 100);             // sleep enough to transmit the 7 plus
                                     // receive 25:  approx 100 uS per char transmit
	char buf[100];
	//const int msgSIZE = 3000;
	//char msg[msgSIZE];
	//int msg_idx = 0;
	
	SAGmsg SAGmessage[2];
	SAGmsg *msg;
	
//	write(fd, "\x00\xFF", 2);
	
	int n;
	int end = 0;
	int dispMsg = 1;
	clock_t start_t,lastmsg_t;
	
	syslog(LOG_INFO, "Starting...");
	
	read_config();
	
	printf("Hello, World!\n");
//	printf("0xDB = ~ 0x%02X = %c\n", (char)~0xDB, 0xDB);
//	printf("/ = 0x%02X\n", '/');
//	printf("! = 0x%02X\n", '!');
	printf("CLOCKS_PER_SEC = %ld\n", CLOCKS_PER_SEC);
//	printf("%04X", 0xAB << 8);
	printf("\n");
	
//	return(0);

	start_t = clock();
	lastmsg_t = clock() + 10*CLOCKS_PER_SEC;	
	
	initMsg(&SAGmessage[0]);
	initMsg(&SAGmessage[1]);
	
	msg = &SAGmessage[0];
	
	while(!end) {
		n = read (fd, buf, 8); //sizeof(buf));  // read up to 100 characters if ready to read
		
		if(n > 0) {
//			write(fd, buf, 1); //echo character for debugging

			//printf("n=%d:\n",n);
			for(int i = 0; i < n; i++) {
				//printf("%X ", buf[i], buf[i+1]);
				//if(i % 100 == 0) {
				//	printf("\n");
				//}
				if(msg->msgIdx >= msgSIZE) {
					msg->msgIdx = 0;
					printf("error: out of buffer\n");
					end = 1;
				}
				
				if(msg->startByte == 0) { // == 0xDB)
					//search for data stream start byte 0xDB
					if(buf[i] != 0xDB) {
						printf("_");
						continue;
					} else {
						msg->msgRaw[0] = buf[i];
						msg->startByte = buf[i];
						msg->msgIdx++;
						if(VERBOSE)
							printf("X");
					}
				} else {
					msg->msgRaw[msg->msgIdx] = buf[i];
					if(VERBOSE)
						printf(".");

					if(msg->msgIdx == 1) { //got length of system title
						msg->sysTitleLen = msg->msgRaw[1];
						
						if(VERBOSE)
							printf("sys title len: %d\n", msg->sysTitleLen);
						if(msg->sysTitleLen != 8) {
							initMsg(msg);
						}
					
					} else if(msg->msgIdx == 1+(msg->sysTitleLen)+3) { //got length of remaining data
						
						msg->sysTitle = &msg->msgRaw[2];
						msg->msgLen = ((int)(msg->msgRaw[2+msg->sysTitleLen+1]) << 8) + (int)(msg->msgRaw[2+msg->sysTitleLen+2]);
						msg->msgLen -= 5+12; //remove frame counter and gcm bytes
						
						if(VERBOSE)
							printf("msgLen: 0x%04X (%d bytes)\n", msg->msgLen, msg->msgLen);

						
//						msg->msgIdx++;

					} else if(msg->msgIdx == 1+msg->sysTitleLen+3+5+msg->msgLen+12) { //received all data
						//msg ready for extract and decoding
						msg->ready2decode = 1;
						
						//prepare to receive new message
						if(VERBOSE)
							printf("\ndone receiving message (");
						if(msg == &SAGmessage[0]) {
							msg = &SAGmessage[1];
							if(VERBOSE)
								printf("0)\n");
						} else {
							msg = &SAGmessage[0];
							if(VERBOSE)
								printf("1)\n");
						}
//						printf(",");
						initMsg(msg);
						msg->msgIdx--;
					}
					msg->msgIdx++;

				}
			}
			//printf("\n");
			lastmsg_t = clock();
		}
		
		for(int i=0; i < 2; i++) {
			if(SAGmessage[i].ready2decode) {
				
				SAGmessage[i].ready2decode = 0;
				
//				BIO_dump_fp(stdout, SAGmessage[i].msgRaw, SAGmessage[i].msgLen+13+5+12);
				
				SAGmessage[i].frameCnt = 0;
				for(int x=0; x < 4; x++) {
					SAGmessage[i].frameCnt <<= 8;
					SAGmessage[i].frameCnt += SAGmessage[i].msgRaw[2+SAGmessage[i].sysTitleLen+1+2+1+x];
				}

				SAGmessage[i].data = &SAGmessage[i].msgRaw[2+SAGmessage[i].sysTitleLen+1+2+1+4];

				memcpy(&SAGmessage[i].gcmTag, &SAGmessage[i].msgRaw[2+SAGmessage[i].sysTitleLen+1+2+1+4+SAGmessage[i].msgLen], 12);

//				SAGmessage[i].gcmTag = {0,0,0,0,0,0,0,0,0,0,0,0};
//				memcpy(&SAGmessage[i].gcmTag, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",12);

				memcpy(&SAGmessage[i].iv, SAGmessage[i].sysTitle, SAGmessage[i].sysTitleLen);
				memcpy(&SAGmessage[i].iv[SAGmessage[i].sysTitleLen], &SAGmessage[i].msgRaw[2+SAGmessage[i].sysTitleLen+1+2+1], 4);
				
				char sysTitle[SAGmessage[i].sysTitleLen+1];
				memcpy(sysTitle, SAGmessage[i].sysTitle, SAGmessage[i].sysTitleLen);
				sysTitle[SAGmessage[i].sysTitleLen+1] = 0;
				
				if(VERBOSE) {
					printf("sys title len: %d\n", SAGmessage[i].sysTitleLen);
					printf("sysTitle: %s\n", sysTitle);
					printf("msgLen: 0x%04X (%d bytes)\n", SAGmessage[i].msgLen, SAGmessage[i].msgLen);
					
					printf("start Byte: %02X\n", SAGmessage[i].startByte);

					printf("frame Counter: 0x%08X (%d)\n", SAGmessage[i].frameCnt, SAGmessage[i].frameCnt);
					printf("data: 0x%02X ... 0x%02X (%d bytes)\n", SAGmessage[i].data[0], SAGmessage[i].data[SAGmessage[i].msgLen-1], SAGmessage[i].msgLen);
					printf("gcm tag: 0x"); //%02X %02X\n", SAGmessage[i].gcmTag[0], SAGmessage[i].gcmTag[1]);
					for(int x=0; x < 12; x++) {
						printf("%02X ",SAGmessage[i].gcmTag[x]);
					}
					printf("\n");
					printf("iv: 0x");
					for(int x=0; x < 12; x++) {
						printf("%02X ", SAGmessage[i].iv[x]);
					}
					printf("\n");
				}
				
				
				aes_gcm_decrypt(&SAGmessage[i]);
				
				time_t rawtime;
				struct tm *info;
				time(&rawtime);
				info = localtime(&rawtime);
				
				sprintf(filename, "/root/programming/smartyMeterReader/data/%s_%04d-%02d-%02d_%02d-%02d-%02d_%d.txt",
						deviceID,
						info->tm_year+1900, info->tm_mon+1, info->tm_mday,
						info->tm_hour, info->tm_min, info->tm_sec,
						SAGmessage[i].frameCnt);
				
				if(VERBOSE)
					printf("filename: %s\n", filename);
				
//				printf("%s", SAGmessage[i].msgDecrypted);
				
				outfile = fopen(filename, "w"); // , O_RDWR | O_NOCTTY | O_SYNC);
				if(outfile) {
					fwrite(SAGmessage[i].msgDecrypted, 1, SAGmessage[i].msgLen, outfile);
					fclose(outfile);
				}
				
				//save msg to file
			}
		}
	}

//	fclose(fp);
	return 0;
}
