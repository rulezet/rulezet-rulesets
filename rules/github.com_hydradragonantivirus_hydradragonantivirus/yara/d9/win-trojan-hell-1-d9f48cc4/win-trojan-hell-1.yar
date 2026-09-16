rule Win_Trojan_Hell_1
{
strings:
	$a0 = { 02300743404975f9595bb80103515253cd135b5a59722de8a000fec1b80102515253cd13 }


condition:
	$a0
}