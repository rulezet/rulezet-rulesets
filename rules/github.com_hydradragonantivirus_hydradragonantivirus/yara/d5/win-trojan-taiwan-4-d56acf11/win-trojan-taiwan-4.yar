rule Win_Trojan_Taiwan_4
{
strings:
	$a0 = { 58004101268c0e5a0007e4210c02e621 }


condition:
	$a0
}