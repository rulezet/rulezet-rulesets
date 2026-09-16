rule Win_Trojan_PS_40
{
strings:
	$a0 = { 8036080028b440b93c02ba3c02cd21b8004233c999cd2159b440ba7d04cd21b801575a }


condition:
	$a0
}