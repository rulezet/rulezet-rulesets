rule Win_Trojan_LdPinch_209
{
strings:
	$a0 = { e8140000004732ca20a1d90882f387c955d9a6ba427fd6 }


condition:
	$a0
}