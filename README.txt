Instructions:

1. In order to run this program, we need to guarantee that we run this project at Linux system.
2. To run run the project we need to get root privilege in Linux system.
3. The correct way to run this code is to tpye “sudo ./rawhttpget http://www.google.com” to test the code
4. Can not use https in this project

process of the code:

The steps of our project is that:
First, we get url from the user’s input, then get local mac, local ip and gateway’s mac. After and get all these data, we start out main function, initially, we used three way handshake to connect with target server. After we got the correct response, we begin to send data request to the target server and got the data back from target server. Finally we got the data we want in the file.


Challenges in this project:

1. Ethernet frames are extremely hard which we need lots of documents to make sure that we could run it in the correct way. Also, AF_PACKET didn’t work well when we first time test the project. We spent time on debugging it and finally we found that we missed a step in arp header. We made it.

2. The second problem is in three way handshake, we sent the data out but we couldn’t receive the data correctly, This is because that we used global variable incorrectly, but it is very hard to debug because through wireshark we couldn’t get which part we made the mistake. Therefore, though it is a small mistake, we still spent some time to debug.

 
