rule Win_Trojan_ARCV_11
{
strings:
	$a0 = { 0674038c167603892678038cc805100033db4b8be3 }


condition:
	$a0
}