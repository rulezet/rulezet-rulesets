rule Win_Trojan_Packed_98
{
strings:
	$a0 = { e80000000090909090909060b80800000033db61a100??4000ffe0 }


condition:
	$a0
}