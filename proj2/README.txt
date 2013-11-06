Logins:	ee122-ed
		ee122-ki

We would rate this project a 8/

The project took around 11 hours.

Extra Credit:

	1) Variable Size Sliding Window
		Emulated how TCP Reno changes its CWND and SSTRESH in order to alter the Sender's window size and sending rate. Everytime a new ack is recieved when CWND < SSTRESH, CWND is incremented by 1. If a new ack is received when CWND > SSTRESH, CWND is incremented by 1/CWND. When three dupacks are received, CWND and SSTRESH are both set to CWND/2. One a timeone, CWND = 1 and SSTRESH = CWND/2.

	2) Selective Acknowleddgements
		Modified the Reciever to send out selective acks, by changing how the Connection class (in Receiver.py) handled out of order acks. Now the adds out of order acks to its res_data list and sends them to the Sender.

	3) Accounting for Variable Round-Trip Times
		Imported time, in order to keep track of RTTs for packets that are sent. Used exponential averaging to determine the estmatedRTT and the Jacobson/Karels algorithm to determine our RTO. However, we set alpha to 0.2 since timeouts are exceedingly random and caused large swings in RTO.

	4) Bi-directional transfer
		Implemented Sender and Receiver functions in both classes. The major difference was to check whether each inccoming packet contained a "start", "data", or "end" message type or if it contained a "ack" message type. Then, handle each packet accordingly depending on its message type.
		These probably don't work since we didn't have time test them.