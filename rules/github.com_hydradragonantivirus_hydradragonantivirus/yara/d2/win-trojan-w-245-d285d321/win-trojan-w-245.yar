rule Win_Trojan_W_245
{
strings:
	$a0 = { 63c7059161d401b4aebd69707420fbc6fec23ef76810270009eb25d21d3f97f00b85bf1121cbcd416464ecfee60b9c42 }


condition:
	$a0
}