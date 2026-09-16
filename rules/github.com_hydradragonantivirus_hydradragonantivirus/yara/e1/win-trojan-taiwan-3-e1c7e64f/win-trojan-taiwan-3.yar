rule Win_Trojan_Taiwan_3
{
strings:
	$a0 = { 210c02e621fbb98000be0000bb80 }


condition:
	$a0
}