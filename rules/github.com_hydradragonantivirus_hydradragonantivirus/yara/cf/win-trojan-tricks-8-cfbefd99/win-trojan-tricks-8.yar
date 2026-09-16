rule Win_Trojan_Tricks_8
{
strings:
	$a0 = { 40008ed8a013001f2c2b8d9c0b01b98d00300743e2fb }


condition:
	$a0
}