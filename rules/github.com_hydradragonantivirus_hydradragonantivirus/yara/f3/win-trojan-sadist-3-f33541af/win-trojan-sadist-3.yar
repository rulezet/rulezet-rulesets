rule Win_Trojan_Sadist_3
{
strings:
	$a0 = { c6045cb908004645268a46002e8804e2f52ec64401008d }


condition:
	$a0
}