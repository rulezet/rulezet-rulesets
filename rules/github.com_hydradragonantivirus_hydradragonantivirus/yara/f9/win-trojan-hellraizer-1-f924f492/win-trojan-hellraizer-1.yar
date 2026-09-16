rule Win_Trojan_HellRaizer_1
{
strings:
	$a0 = { d1cd217303e9aafeb8004233c933d2cd21b91800b440ba7a03cd217303e992fec3b440b9af038bd1cd2133c933d2b80042cd21b440b90400ba7203cd21c3b003 }


condition:
	$a0
}