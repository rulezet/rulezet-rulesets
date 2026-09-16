rule Win_Trojan_GR_5
{
strings:
	$a0 = { bd6303f9b445cd2149bee1ec902629b5 }


condition:
	$a0
}