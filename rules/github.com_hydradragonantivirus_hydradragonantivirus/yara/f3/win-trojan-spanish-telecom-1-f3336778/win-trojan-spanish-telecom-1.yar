rule Win_Trojan_Spanish_Telecom_1
{
strings:
	$a0 = { 8b1db20083fb007418bf5500b2 }


condition:
	$a0
}