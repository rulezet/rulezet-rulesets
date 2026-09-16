rule Win_Trojan_LoveGate_1
{
strings:
	$a0 = { 3d473bf763fd502d3b11fb45ecf407c02b20665e6cca975b3a81e5a4eb9a5f9649bce1a838ae24e9a31026b1b5fa206e75183e296418b4fa1bac93d72f44163f63c58212e49611fcdafa6d2d5103fa }


condition:
	$a0
}