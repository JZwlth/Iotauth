#include "c_common.h"

void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void print_buf(unsigned char * buf, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", buf[i]);
    printf("\n");
}

// nonce generator;
void generate_nonce(int length, unsigned char * buf)  
{
    int x = RAND_bytes(buf, length);
    if(x == -1)
    {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}   

// num: number to write in buf, n: buf size 
void write_in_n_bytes(int num, int n, unsigned char * buf)
{
        for(int i=0 ; i < n; i++)
        {
            buf[i] |=  num >> 8*(n-1-i);
        }
}

//read variable int buffer 'buf' in Big Endian with length of 'byte_length' into unsigned int num
/*TODO: 영빈이형 체크
형 코드 read_variable_unsigned int 부분과 print_seq_num 부분과 겹침. 

확인시 TODO 지울것.
*/


unsigned int read_unsigned_int_BE(unsigned char * buf, int byte_length)
{
    int num =0;
    for(int i =0; i<byte_length;i++)
    {
        num |= buf[i]<< 8*(byte_length-1-i);
    }
    return num; 
}

//TODO: 밑에 합쳐놓은 버전 있음.line 75 영빈이형 체크.
//내 기억으로 까인 이유는 내가 struct 써서 까인거 같은데 같은 기능하면 하나로 있는게 효율적이지 않나... 형껄로하면 비트 shifting을 두번 해야함.
/*  
    function: (0,127) = 1, [128, 128^2] = 2, [128^2, 128^3] = 3 ..... 
    input: integer buffer to change
    return: payload_buf_length
*/
unsigned int payload_buf_length(int b)
{   
    int n = 1;
    while(b > 127)
    {
        n += 1;
        b >>=7;
    }
    return n;
}
/*return: message length of the payload
input: buffer from after messagetype, 
buf_length: total read message length
*/
unsigned int var_length_int_to_num_t(unsigned char * buf, int buf_length)
{
    int num = 0;
    for (int i =0; i<buf_length; i++)
    {
        num |= (buf[i]& 127) <<(7 * i);
        if((buf[i]&128) == 0 )
        {
            break;
        }
    }
    return num;
}

//영빈이형 이거 check. 위에 두개 한번으로 합쳐놓은거. 
void var_length_int_to_num(unsigned char * buf, unsigned int buf_length, unsigned int * payload_length, unsigned int * payload_buf_length)
{
    unsigned int num = 0;
    *payload_buf_length = 0;
    for( int i = 0; i < buf_length; i++) { 
        num |= (buf[i] & 127) << (7 * i);
        if ((buf[i] & 128) == 0) {
            *payload_length = num;
            *payload_buf_length= i +1;
            break;
        }
    }
}

/*
function: parses received message into 'message_type', and data after msg_type+payload_buf to 'data_buf'

USAGE:
unsigned char received_buf[1000];
unsigned int received_buf_length = read(socket, received_buf, sizeof(received_buf));
unsigned char mesage_type;
unsigned int data_buf_length;
unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length)
*/
unsigned char * parse_received_message(unsigned char * received_buf, unsigned int received_buf_length, unsigned char * message_type, unsigned int * data_buf_length)
{
    *message_type = received_buf[0];
    unsigned int payload_buf_length; 
    var_length_int_to_num(received_buf + MESSAGE_TYPE_SIZE, received_buf_length, data_buf_length, &payload_buf_length);
    return received_buf + MESSAGE_TYPE_SIZE + payload_buf_length; //msgtype+payload_buf_length;
}


/*parse_session_message

only need to know make_sender_buf()

function: Makes sender_buf with 'payload' and 'MESSAGE_TYPE' to 'sender'.
          User only needs to write() the sender buffer.
input: data to send., message_type, pointer to save.

**** max byte of data length is 2^35bit = 4GB

*/


void num_to_var_length_int(unsigned int data_length, unsigned char * payload_buf, unsigned char * buf_len)
{
    *buf_len= 1;
    while(data_length > 127)
    {
        payload_buf[*buf_len-1] = 128 | data_length & 127;
        *buf_len += 1;
        data_length >>=7;
    }
    payload_buf[*buf_len-1] = data_length;
}

void make_buffer_header(unsigned char *data, unsigned int data_length, unsigned char MESSAGE_TYPE, unsigned char *header, unsigned int * header_length)
{
    unsigned char payload_buf[MAX_PAYLOAD_BUF_SIZE]; //우선 5byte로 잡기.
    unsigned char payload_buf_len;
    num_to_var_length_int(data_length, payload_buf, &payload_buf_len);
    *header_length = MESSAGE_TYPE_SIZE + payload_buf_len;
    header[0] = MESSAGE_TYPE;
    memcpy(header + MESSAGE_TYPE_SIZE, payload_buf, payload_buf_len);
}

void concat_buffer_header_and_payload(unsigned char *header, unsigned int header_length, unsigned char *payload, unsigned int payload_length, unsigned char *ret, unsigned int * ret_length)
{
    memcpy(ret, header, header_length);
    memcpy(ret + header_length, payload, payload_length);
    *ret_length = header_length + payload_length;
}

void make_sender_buf(unsigned char *payload, unsigned int payload_length, unsigned char MESSAGE_TYPE, unsigned char *sender, unsigned int * sender_length)
{
    unsigned char header[MAX_PAYLOAD_BUF_SIZE+1];
    unsigned int header_length;
    make_buffer_header(payload, payload_length, MESSAGE_TYPE, header, &header_length);
    concat_buffer_header_and_payload(header, header_length, payload, payload_length, sender, sender_length);
}

/*
function: Connects to server as client. Maybe the entity client-Auth, entity_client - entity_server, entity_server - Auth.
input:  sock: The target socket.
        ip_addr: The target ip_address to connect to.
        port_num: The target port number
return: socket number.

usage:
    int sock;
    connection(&sock, IP_ADDRESS, PORT_NUM);
*/

void connect_as_client(const char * ip_addr, const char * port_num, int * sock)
{
    struct sockaddr_in serv_addr;
    int str_len;
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*sock == -1){
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; //IPv4
    serv_addr.sin_addr.s_addr = inet_addr(ip_addr); //the ip_address to connect to
    serv_addr.sin_port = htons(atoi(port_num));
    if(connect(*sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        error_handling("connect() error!");
    }
    printf("\n\n------------Connected-------------\n");
}

/*
function:   serializes handshake nonces and reply nonces.
            ret:indicator_1byte + nonce_8byte + reply_nonce_8byte
            The size of this buf is constant to HS_INDICATOR_SIZE

input:  nonce(my_nonce) & reply_nonce(received_nonce)
usage: 
        unsigned int buf_length = HS_INDICATOR_SIZE;
        unsigned char buf[HS_INDICATOR_SIZE];
        serialize_handshake(my_nonce, received_nonce, buf);
        ~~use buf~~
        free(buf);
*/
void serialize_handshake(unsigned char * nonce, unsigned char * reply_nonce, unsigned char * ret)
{
    if(nonce == NULL && reply_nonce == NULL){
        error_handling("Error: handshake should include at least on nonce.");
    }
    unsigned char indicator = 0;
    if(nonce != NULL){
        indicator += 1;
        memcpy(ret+1, nonce, HS_NONCE_SIZE);
    }
    if(reply_nonce != NULL){
        indicator += 2;
        memcpy(ret+1+HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    //TODO: add dhParam options.
    ret[0] = indicator;
}

//TODO: check.왜 1,2,4 지??
void parse_handshake(unsigned char *buf,  HS_nonce * ret)
{
    if((buf[0] & 1) != 0){
        memcpy(ret->nonce, buf +1, HS_NONCE_SIZE);
    }
    if((buf[0] & 2) != 0){
        memcpy(ret->reply_nonce. buf +1 +HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
    if((buf[0] & 4) != 0){
        memcpy(ret->dhParam, buf +1 + HS_NONCE_SIZE*2, HS_NONCE_SIZE);
    }
}

void receive_message (unsigned char * ret, unsigned int * ret_length, unsigned int * seq_num, unsigned char * payload, unsigned int payload_length, parsed_session_key *parsed_session_key){
    //TODO: check validity
    
    unsigned char into[512];
    unsigned int into_length;
    memcpy(into, payload, payload_length);
    into_length = payload_length;
    unsigned char data[512];
    unsigned int data_length;
    symmetric_decrypt_authenticate(data, &data_length, into, into_length, &parsed_session_key->keys);
    parse_session_message(ret, ret_length, seq_num, data, data_length);
    printf("Received seq_num: %d\n", *seq_num);
}


void parse_session_message(unsigned char * ret, unsigned int * ret_length, unsigned int *seq_num, unsigned char * buf, unsigned int buf_length){
    *seq_num = read_unsigned int_BE(buf, 0, SEQ_NUM_SIZE);
    memcpy(ret, buf+SEQ_NUM_SIZE, buf_length - SEQ_NUM_SIZE );
    *ret_length = buf_length - SEQ_NUM_SIZE;
}