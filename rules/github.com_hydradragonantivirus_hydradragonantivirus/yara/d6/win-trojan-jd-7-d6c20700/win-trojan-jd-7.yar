rule Win_Trojan_JD_7
{
strings:
	$a0 = { 6401b440cd2133c9b8004299cd21b440b104ba6202cd21 }


condition:
	$a0
}