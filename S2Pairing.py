try:
    from rflib import RfCat as rfcat
except ImportError:
    print "Error : rflib not installed, RFCat will not work\n"
else:
    from rflib import SYNCM_CARRIER_15_of_16, MOD_2FSK, ChipconUsbTimeoutException
import time
import binascii
import sys
import ZEncryption
from re import split, sub
from eccsnacks.curve25519 import scalarmult, scalarmult_base

# Checks the Z-wave checksum
def checksum(data):
    b = 255
    for i in range(2, len(data)):
        b ^= int(data[i].encode("hex"), 16)
    print "\t-> Checksum :", format(b, '02x')
    return format(b, '02x').decode("hex")

# Inverts Bytes of the input data
def invert(data):
    datapost = ''
    for i in range(len(data)):
        datapost += chr(ord(data[i]) ^ 0xFF)
    return datapost

# Calculates Z-wave checksum for a given message
def calculate_checksum(data):
    checksum = 0xff
    for i in range(len(data)):
        checksum ^= ord(data[i])
    return checksum

# Setup the Dongle for 40 kbps communication
def setup():
        d = rfcat(0, debug=False)

        # Thanks to killerzee
        d.setFreq(868399841)
        d.setMdmModulation(MOD_2FSK)
        d.setMdmSyncWord(0xaa0f)
        d.setMdmDeviatn(20629.883)
        d.setMdmChanSpc(199951.172)
        d.setMdmChanBW(101562.5)
        d.setMdmDRate(39970.4)
        d.makePktFLEN(48)
        d.setEnableMdmManchester(False)
        d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
	d.setMaxPower
	return d

#Setup the Dongle for 9.6 kbps communication
def setup2():
	d = rfcat(1, debug=False)

        d.setFreq(868399841)
        d.setMdmModulation(MOD_2FSK)
        d.setMdmSyncWord(0xaa0f)
        d.setMdmDeviatn(20629.883)
        d.setMdmChanSpc(199951.172)
        d.setMdmChanBW(101562.5)
        d.setMdmDRate(9600)
        d.makePktFLEN(48)
        d.setEnableMdmManchester(False)
        d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
	return d

#Recieve a 40 kbps message (Based on https://github.com/advens/Z-Attack)
def recieveMessage(d):

	global frame_nb
        payload = ""
        res = ""


    	try:
		# RFCat
                res = d.RFrecv(10)[0]
                # Invert frame for 40Mhz Bandwith - cf BH 2013 (sensepost)
                res = invert(res)

    	except ChipconUsbTimeoutException:
        	pass

	if res:
	    print ""

	    # Check is several frames in one
	    frames = split("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\xf0", res)

	    for frame in frames:

		res = frame
		print ""

		# Control the length of the frame
		try:
		    length = ord(res[7])
		    res = res[0:length]
		    # Check CRC and remove noise
		    fcs = res[-1]
		    res = res[:-1]  # Remove FCS
		    calculated_checksum_frame = calculate_checksum(res)
		    if calculated_checksum_frame != ord(fcs):
		        res = ""
		except:
		    # Problem during Checksum process (frame too short?)
		    x = 0




		if res:  # if we still have a frame to decode
		    res = res.encode("hex")

		    # PATCH REMOVE UNUSEFUL DATA (Do not know why :-))
		    res = sub(r'00[0-1][0-1][0-1][a-f0-9]', '', res)
		    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000', '', res)
		    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]', '', res)

		    # Decode Zwave frame
		    home_id = res[0:8]
		    src_node = res[8:10]
		    FrameControl = res[10:14]
		    length = res[14:16]
		    dst_node = res[16:18]
		    payload = res[18:]

		    if length == "0a":  # ACK frame is a 0 byte payload => 0A cf G.9959
		        print "\tACK response from " + src_node + " to "+dst_node
		        decoded_payload = "ACK"

		    if 0 < len(payload) < 128:  # Payload for Z-Wave 64 bytes max
		        print "\tZ-Wave frame:"
		        print "\t\tHomeID=", home_id
		        print "\t\tSrcNode=", src_node
		        print "\t\tDstNode=", dst_node
			print "\t\tFrameControl=", FrameControl
			print "\t\tPayload=", payload
		        print "\t\tChecksum=", fcs.encode("hex")

		        if dst_node == "ff":
		            print "\t\t[*] Broadcast frame"
	return res

#Recieve a 9.6 kbps message (These are Manchester encoded but will be recieved as NRZ)
def recieveMessageManchester(d):

        payload = ""
        res = ""

    	try:
		# RFCat
		res = d.RFrecv(10)[0]
		# Message is manchester encoded and needs to be shifted by one bit
		integer = int(res.encode("hex"), 16 )
		binary_string = "1" + format(integer, '0>42b')[:-1]
		message = '%08X' % int(binary_string, 2)

    	except ChipconUsbTimeoutException:
        	pass

	if res:
		    length = ord(res[7])-1
		    res = message
		    res = res[0:length]
	            print ""

		    # PATCH REMOVE UNUSEFUL DATA (Do not know why :-))
		    res = sub(r'00[0-1][0-1][0-1][a-f0-9]', '', res)
		    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000', '', res)
		    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]', '', res)

		    # Decode Zwave frame
		    home_id = res[0:8]
		    src_node = res[8:10]
		    FrameControl = res[10:14]
		    length = res[14:16]
		    dst_node = res[16:18]
		    payload = res[18:]

		    if length == "0a":  # ACK frame is a 0 byte payload => 0A cf G.9959
			print "\tACK response from " + src_node + " to "+dst_node
			decoded_payload = "ACK"

		    if 0 < len(payload) < 128:  # Payload for Z-Wave 64 bytes max
			print "\tZ-Wave frame:"
			print "\t\tHomeID=", home_id
			print "\t\tSrcNode=", src_node
			print "\t\tDstNode=", dst_node
			print "\t\tFrameControl=", FrameControl
			print "\t\tPayload=", payload

			if dst_node == "ff":
				    print "\t\t[*] Broadcast frame"
	return res

# Sends an ack message with dongle (d). Takes senderID and seq as parameter
def sendAck(nodeId, seq, d):
	newAck =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x03' + seq.decode("hex") + '\x0A\x01'
	d.RFxmit(invert(newAck + chr(calculate_checksum(newAck))))


#ECDH keys (Hardcoded, these can be calculated every time if needed)
pKey = "c090c06c64bc9c2ad8d03cd90203bbf362a2df16277feecf6939de677c17c870"
pubKey = "83cae18106e477f41b4c7850f7971834877dd696a406bd6607d6979cba56db1a"


#Setting up a reciever at 9.6 Kbit/s and sender at 40 Kbit/s
s = setup2()
d = setup()

#Broadcast Node info (Pair as Door Lock, this can be  adapted to join as another type of device)
nodeInfo =  '\xFD\xC8\x05\x47\x00\x01\x41\x15\xFF\x01\x01\x53\xDC\x01\x40\x03\x5E\x55\x98\x9F'
d.RFxmit(invert(nodeInfo + chr(calculate_checksum(nodeInfo))))


#Wait for Assign ID
start = time.time()
res = ''
nodeId = ''
ackSeq = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessageManchester(s)

        #HomeID will be the temporary homeID used in the Node Info
		if res[0:8] == "FDC80547":
			print ''
			nodeId = res[16:18]
			print ''
			print "Id Assigned:", nodeId
			print ''
			ackSeq = res[12:14]
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()


#sendAck
oldAck =  '\xFD\xC8\x05\x47\x00\x03' + ackSeq.decode("hex") + '\x0A\x01'
d.RFxmit(invert(oldAck + chr(calculate_checksum(oldAck))))

#Wait for NOP
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessageManchester(s)
		if res[0:8] == "C01F9E67":
			print ''
			print "First NOP recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()

#sendAck
newAck =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x03' + ackSeq.decode("hex") + '\x0A\x01'
d.RFxmit(invert(newAck + chr(calculate_checksum(newAck))))

#From here on all communication will be in 40 Kbit/s

#Wait for NOP2 (When the Controller detects a 40 Kbit/s ack it seems to resend his message in 40 Kbit/s)
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67":
			print ''
			print "Second NOP recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()

#sendAck
newAck =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x03' + ackSeq.decode("hex") + '\x0A\x01'
d.RFxmit(invert(newAck + chr(calculate_checksum(newAck))))

#wait for Find Nodes
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "0104":
			print ''
			print "FIND nodes recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()


#sendAck
sendAck(nodeId, ackSeq, d)


#wait for Get Nodes
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "0105":
			print ''
			print "Get Nodes recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()

#sendAck
sendAck(nodeId, ackSeq, d)

#wait for KEX get
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f04":
			print ''
			print "KEX get recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, pairing failed"
		d.setModeIDLE()
		s.setModeIDLE()
		sys.exit()

#sendAck
sendAck(nodeId, ackSeq, d)

seq = 1

#send KEX report
KEXreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41' + chr(seq) + '\x10\x01\x9F\x05\x00\x02\x01\x84'
d.RFxmit(invert(KEXreport + chr(calculate_checksum(KEXreport))))

#wait for KEX set
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 3):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f06":
			print ''
			print "KEX set recieved"
			print ''
			ackSeq = res[12:14]
		else:
			res = ''
	else:
		print "No response, Resending report"
		KEXreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41' + chr(seq) + '\x10\x01\x9F\x05\x00\x02\x01\x84'
		d.RFxmit(invert(KEXreport + chr(calculate_checksum(KEXreport))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)

#send PUB report (First 2 Bytes of the send key need to be set to /x00 and the real values will have to be manually input to the controller (in decimal notation) in the case of the hardcoded pub key it is 33738)
shortKey = "e18106e477f41b4c7850f7971834877dd696a406bd6607d6979cba56db1a"
PUBreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x45\x2D\x01\x9F\x08\x00\x00\x00' + shortKey.decode("hex")
d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))


#wait for PUB report
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 5):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f08":
			controllerKey = res[24:88]
			print ''
			print "PUB report recieved", controllerKey
			print ''
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, Resending report"
		d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)

#Derive session key (Shared secret established via Curve25519)
sessionKey = scalarmult(pKey.decode("hex"),controllerKey.decode("hex")).encode("hex")



print ''
print "Session key calculated:", sessionKey
print ''

#send Nonce Get
PUBreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x46\x0D\x01\x9F\x01\x00'
d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))

#wait for Nonce Report
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 4):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f02":
			recieverEntropy = res[26:58]
			print ''
			print "Nonce Report Recieved:", recieverEntropy
			print ''
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, resending get"
		PUBreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x46\x0D\x01\x9F\x01\x00'
		d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)

#Calculate TempKey and Nonce
senderEntropy = b"\x0D\xF5\x62\x4D\x0F\x84\xBE\xE0\xDA\x85\x95\x37\x8C\x2E\x24\xBB"
recieverEntropy = bytearray.fromhex(recieverEntropy)
sessionKey = bytearray.fromhex(sessionKey)
MEI = ZEncryption.CKDFMEIExpand(ZEncryption.CKDFMEIExtract(senderEntropy, recieverEntropy))
expand = ZEncryption.CKDFTempExpand(ZEncryption.CKDFTempExtract(sessionKey, controllerKey.decode("hex"), pubKey.decode("hex")))
encryptionKey = expand[0]
personalisation_string = expand[1]
drbg = ZEncryption.instantiateCTR(MEI, personalisation_string)
nonce = ZEncryption.generateNonce(drbg)

#Create aad for Authentication
senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x24"
seq = b"\x82"
extension = b"\x01\x12\x41\x0D\xF5\x62\x4D\x0F\x84\xBE\xE0\xDA\x85\x95\x37\x8C\x2E\x24\xBB"
aad = senderID + destinationID + homeID + length + seq + extension

#Encrypt message
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x9F\x06\x01\x02\x01\x04")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x47\x2E\x01\x9F\x03\x82\x01\x12\x41\x0D\xF5\x62\x4D\x0F\x84\xBE\xE0\xDA\x85\x95\x37\x8C\x2E\x24\xBB' + cipherText[1].decode("hex") + cipherText[2].decode("hex")

#send KEX get Echo
time.sleep(4)
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))

#wait for confirmation
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 4):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f03":
			print "Confirmation Recieved:", recieverEntropy
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, resending Echo"
		d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)

#Generate next nonce (Twice because the 2nd nonce was used by the controller send us a message so we need the 3th)
nonce = ZEncryption.generateNonce(drbg)
nonce = ZEncryption.generateNonce(drbg)

#Create aad for Authentication
senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x0F"
seq = b"\x83"
extension = b"\x00"
aad = senderID + destinationID + homeID + length + seq + extension

#Encrypt message
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x9F\x09\x04")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x0E\x19\x01\x9F\x03\x83\x00' + cipherText[1].decode("hex") + cipherText[2].decode("hex")

#Send Network Key get (Only the S2 key should be asked (if other keys are wanted, this has to be done multiple times (once per key)))
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))

#wait for Network key Report
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 4):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f03":
			nonce = ZEncryption.generateNonce(drbg)
			networkKey = ZEncryption.zDecrypt(encryptionKey, nonce, res[26:64].decode("hex"),"", aad)[6:]
			print "Network Key Recieved:", networkKey
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, resending Get"
		d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)

#send Nonce Get
PUBreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x47\x0D\x01\x9F\x01\x00'
d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))

#wait for Nonce Report
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 4):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f02":
			recieverEntropy = res[26:64]
			print ''
			print "Nonce Report Recieved:", recieverEntropy
			print ''
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, resending get"
		PUBreport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x46\x0D\x01\x9F\x01\x00'
		d.RFxmit(invert(PUBreport + chr(calculate_checksum(PUBreport))))
		start = time.time()

#sendAck
sendAck(nodeId, ackSeq, d)


#Calculate new Nonce and Key (Based on new entropy and the recieved network key)
senderEntropy = b"\x1D\xF9\x63\x4D\x0F\x89\xBE\xE5\xDA\x95\x95\x37\x8C\x2E\x24\xBB"
recieverEntropy = recieverEntropy.decode("hex")
networkKey = networkKey.decode("hex")
MEI = ZEncryption.CKDFMEIExpand(ZEncryption.CKDFMEIExtract(senderEntropy, recieverEntropy))
expand = ZEncryption.CKDFNetworkKeyExpand(networkKey)
encryptionKey = expand[0]
personalisation_string = expand[1]
drbg = ZEncryption.instantiateCTR(MEI, personalisation_string)
nonce = ZEncryption.generateNonce(drbg)

#Create aad for Authentication
senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x20"
seq = b"\x05"
extension = b"\x01\x12\x41\x1D\xF9\x63\x4D\x0F\x89\xBE\xE5\xDA\x95\x95\x37\x8C\x2E\x24\xBB"
aad = senderID + destinationID + homeID + length + seq + extension

#Encrypt Message
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x9F\x0B")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x48\x2A\x01\x9F\x03\x05\x01\x12\x41\x1D\xF9\x63\x4D\x0F\x89\xBE\xE5\xDA\x95\x95\x37\x8C\x2E\x24\xBB' + cipherText[1].decode("hex") + cipherText[2].decode("hex")

#send Network Key verify
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))

#wait for Nonce Get
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f01":
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, Resending verify"
		start = time.time()
		d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))


#sendAck
sendAck(nodeId, ackSeq, d)



#send Nonce Report
recieverEntropy = b"\x0D\xF5\x52\x4D\x8F\x14\xBE\x10\xDA\x85\x96\x37\x8C\x2E\x24\xBB"
nonceReport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x49\x1E\x01\x9F\x02\x06\x01' + recieverEntropy
d.RFxmit(invert(nonceReport + chr(calculate_checksum(nonceReport))))

#wait for Transfer End
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 5):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f03":
			ackSeq = res[12:14]
			senderEntropy = res[30:62].decode("hex")
			print ''
			print "Sender Entropy Recieved:", res[30:62]
			print ''


		else:
			res = ''
	else:
		print "No response, resend Nonce Report"
		start = time.time()
		d.RFxmit(invert(nonceReport + chr(calculate_checksum(nonceReport))))

#sendAck
sendAck(nodeId, ackSeq, d)

#Calculate Nonce and Encryption key based on new entropy and the TempCCMKey obtained with Curve25519
MEI = ZEncryption.CKDFMEIExpand(ZEncryption.CKDFMEIExtract(senderEntropy, recieverEntropy))
expand = ZEncryption.CKDFTempExpand(ZEncryption.CKDFTempExtract(sessionKey, controllerKey.decode("hex"), pubKey.decode("hex")))
encryptionKey = expand[0]
personalisation_string = expand[1]
drbg = ZEncryption.instantiateCTR(MEI, personalisation_string)
nonce = ZEncryption.generateNonce(drbg)
nonce = ZEncryption.generateNonce(drbg)

#Create aad for Authentication
senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x0F"
seq = b"\x07"
extension = b"\x00"
aad = senderID + destinationID + homeID + length + seq + extension
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x9F\x0C\x01")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x4A\x19\x01\x9F\x03\x07\x00' + cipherText[1].decode("hex") + cipherText[2].decode("hex")

#send Transfer End
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))

#wait for Request Info
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 5):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "0102":
			ackSeq = res[12:14]
			senderEntropy = res[30:62].decode("hex")
			print ''
			print "Request Info Recieved"
			print ''


		else:
			res = ''
	else:
		print "No response, resend Transfer end"
		start = time.time()
		d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))

#sendAck
sendAck(nodeId, ackSeq, d)

#Send Node info
nodeInfo =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x4D\x15\x01\x01\x01\x53\xDC\x01\x40\x03\x5E\x55\x98\x9F'
d.RFxmit(invert(nodeInfo + chr(calculate_checksum(nodeInfo))))

#wait for Nonce Get
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 10):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f01":
			ackSeq = res[12:14]

		else:
			res = ''
	else:
		print "No response, Resending node Info"
		start = time.time()
		d.RFxmit(invert(nodeInfo + chr(calculate_checksum(nodeInfo))))

#sendAck
sendAck(nodeId, ackSeq, d)

#send Nonce Report
recieverEntropy = b"\x0D\xF5\x52\x8D\x9F\x54\xBE\x10\xDE\x85\x96\x37\x8C\x2E\x24\xBB"
nonceReport =  '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x49\x1E\x01\x9F\x02\x06\x01' + recieverEntropy
d.RFxmit(invert(nonceReport + chr(calculate_checksum(nonceReport))))

#wait for Supported Get
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 5):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f03":
			ackSeq = res[12:14]
			senderEntropy = res[30:62].decode("hex")
			print ''
			print "Sender Entropy Recieved:", res[30:62]
			print ''


		else:
			res = ''
	else:
		print "No response, resend Nonce Report"
		start = time.time()
		d.RFxmit(invert(nonceReport + chr(calculate_checksum(nonceReport))))

#sendAck
sendAck(nodeId, ackSeq, d)

#send Supported Report
MEI = ZEncryption.CKDFMEIExpand(ZEncryption.CKDFMEIExtract(senderEntropy, recieverEntropy))
expand = ZEncryption.CKDFNetworkKeyExpand(networkKey)
encryptionKey = expand[0]
personalisation_string = expand[1]
drbg = ZEncryption.instantiateCTR(MEI, personalisation_string)
nonce = ZEncryption.generateNonce(drbg)
nonce = ZEncryption.generateNonce(drbg)

senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x1E"
seq = b"\xCA"
extension = b"\x00"
aad = senderID + destinationID + homeID + length + seq + extension
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x9F\x0E\x71\x8A\x8B\x4C\x4E\x70\x86\x72\x5a\x73\x80\x62\x63\x85\x59\x6c")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x48\x28\x01\x9F\x03\xCA\x00' + cipherText[1].decode("hex") + cipherText[2].decode("hex")
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))


#wait for + info Get
start = time.time()
res = ''
while res == '':
	end = time.time()
	if (end - start < 5):
		res = recieveMessage(d)
		if res[0:8] == "c01f9e67" and res[18:22] == "9f03":
			ackSeq = res[12:14]


		else:
			res = ''
	else:
		print "No response, Pair Finished"
		start = time.time()
		d.setModeIDLE()
		s.setModeIDLE()
		sys.out()

#sendAck
sendAck(nodeId, ackSeq, d)

#send Supported  + Report

nonce = ZEncryption.generateNonce(drbg)
nonce = ZEncryption.generateNonce(drbg)

senderID = bytearray.fromhex(nodeId)
destinationID = b"\x01"
homeID = b"\xC0\x1F\x9E\x67"
length = b"\x00\x15"
seq = b"\xCB"
extension = b"\x00"
aad = senderID + destinationID + homeID + length + seq + extension
cipherText = ZEncryption.zEncrypt(encryptionKey, nonce, aad, b"\x5e\x02\x01\x07\x00\x03\x00\x03\x00")
encryptedMessage = '\xC0\x1F\x9E\x67' + nodeId.decode("hex") + '\x41\x49\x1F\x01\x9F\x03\xCB\x00' + cipherText[1].decode("hex") + cipherText[2].decode("hex")
d.RFxmit(invert(encryptedMessage + chr(calculate_checksum(encryptedMessage))))





print("Done")


d.setModeIDLE()
s.setModeIDLE()
