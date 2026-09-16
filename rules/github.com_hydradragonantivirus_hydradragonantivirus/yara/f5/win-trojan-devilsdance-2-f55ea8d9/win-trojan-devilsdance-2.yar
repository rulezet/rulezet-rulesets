rule Win_Trojan_DevilsDance_2
{
strings:
	$a0 = { 01508cc88ed88ec0c306b82135cd }


condition:
	$a0
}