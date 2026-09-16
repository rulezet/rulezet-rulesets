rule Win_Trojan_Trojan_208
{
strings:
	$a0 = { c6865f0703b41a8d963407cd21b44790b2008db6f406 }


condition:
	$a0
}