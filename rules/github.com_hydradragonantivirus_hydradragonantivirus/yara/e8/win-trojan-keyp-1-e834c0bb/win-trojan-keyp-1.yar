rule Win_Trojan_KEYP_1
{
strings:
	$a0 = { d2bb007ecd13722ba113042ea3bb852d0700a31304061fb106d3e08ec0be007e33ffb90014fcf3 }


condition:
	$a0
}