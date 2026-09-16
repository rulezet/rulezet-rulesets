rule Win_Trojan_PS_39
{
strings:
	$a0 = { 90b90b013bcb750240902e81354222483bc17502904b83c70290e2ee }


condition:
	$a0
}