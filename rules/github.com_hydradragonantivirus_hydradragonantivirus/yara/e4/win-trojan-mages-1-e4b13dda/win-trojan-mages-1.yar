rule Win_Trojan_Mages_1
{
strings:
	$a0 = { 8036080028b440b95a02ba5a02cd21b8004233c999cd2159b440bab904cd21b801575a }


condition:
	$a0
}