rule Win_Trojan_Stranger_1
{
strings:
	$a0 = { 50be31008bc681c600018bde5681c621008bfeb9bd02ac2ac4aafec4e2f8 }


condition:
	$a0
}