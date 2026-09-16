rule Win_Trojan_Bob_2
{
strings:
	$a0 = { 0242cd21b9ba02b440bac000cd21 }


condition:
	$a0
}