rule Win_Trojan_W_62
{
strings:
	$a0 = { 81ed07104000b8e02e7249be2810400003f5b968010000310646464646e2f8 }


condition:
	$a0
}