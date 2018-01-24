# An implementation of the TCP protocol using the Minet stack
Implements the TCP protocol using the Minet stack to the specifications layed out in RFC 793 with some exceptiosn.

## Exceptions
You only need to implement Go-Back-N


You do not have to support outstanding connections (i.e., an incoming connection
queue to support the listen backlog) in a passive open.

You do not have to implement congestion control.

You do not have to implement support for the URG and PSH flags, the urgent
pointer, or urgent (out-of-band) data.

You do not have to support TCP options.

You do not have to implement a keep-alive timer

You do not have to implement the Nagle algorithm.

You do not have to implement delayed acknowledgements.

You do not have to generate or handle ICMP errors.

You may assume that simultaneous opens and closes do not occur

You may assume that sock_module only makes valid requests (that is, you do not
have to worry about application errors)

You may assume that exceptional conditions such as aborts do not occur.

You should generate IP packets no larger than 576 bytes, and you should set your

MSS (maximum [TCP] segment size) accordingly, to 536 bytes. Notice that this
is the default MSS that TCP uses if there is no MSS option when a connection is
negotiated

## Usage
To use replace the tcp_module.cc stub in /src/modules in the Minet folder and run Minet.
