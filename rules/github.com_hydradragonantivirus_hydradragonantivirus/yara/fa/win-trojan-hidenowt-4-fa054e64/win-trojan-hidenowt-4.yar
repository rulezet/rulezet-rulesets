rule Win_Trojan_Hidenowt_4
{
strings:
	$a0 = { 0e07268c55102689651257b9100033f68edef3a458fabc }


condition:
	$a0
}