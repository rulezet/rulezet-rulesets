rule Win_Trojan_Sister_4
{
strings:
	$a0 = { 0e0e071fbe14008bfeb9ba01ad050000abe2f9 }


condition:
	$a0
}