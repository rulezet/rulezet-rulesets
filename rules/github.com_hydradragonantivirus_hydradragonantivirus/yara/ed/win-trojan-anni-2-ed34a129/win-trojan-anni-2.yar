rule Win_Trojan_Anni_2
{
strings:
	$a0 = { 8db63d01568b961802b96d008bfefcad33c2abe2fac3 }


condition:
	$a0
}