rule Win_Trojan_Norway_1
{
strings:
	$a0 = { 36030181c60501893600018bee8d761e90b98302803429802c5d46e2f7 }


condition:
	$a0
}