rule Win_Trojan_Bg_2
{
strings:
	$a0 = { 60be1300b2??2e3014c0c2??4681fe440576f3ca }


condition:
	$a0
}