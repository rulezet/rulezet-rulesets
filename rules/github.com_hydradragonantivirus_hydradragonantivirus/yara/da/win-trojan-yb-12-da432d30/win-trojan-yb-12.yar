rule Win_Trojan_YB_12
{
strings:
	$a0 = { 0143cd21b80057cd218994a401898ca60133c933d2b80242cd218bd6b9d301b440cd2133c933d2 }


condition:
	$a0
}