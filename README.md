## Group Members
Taimah Williams:

    E-mail: tkw10@pitt.edu
    
    Username: tkw10
Bob Colleran:

    E-mail: rjc59@pitt.edu
    
    Username: rjc59
    
## Included files
tcp_module.cc

## Compilation steps
Source files go in src/modules, run the Makefile in the minet folder, start minet and run a tcp server in user space

## What works
-Handshakes both from passive and active open
--- there are issues with active opens if the port is still open on the server side
-Handshakes for passive and active closes
--- I couldn't get passive closes to send the final ack without doing a FINACK instead of just a FIN (netcat wouldn't send me the final ACK)
--- The minet stack crashes whenever I close, not sure if this is intended but I doubt it is
-Data transfers, at least small ones should work from both ends, I didn't test with large ones
