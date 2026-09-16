rule Win_Trojan_Small_4073
{
strings:
	$a0 = { c8000000c97431e87d00000031ed81c5??????fff7dd01dd }


condition:
	$a0
}