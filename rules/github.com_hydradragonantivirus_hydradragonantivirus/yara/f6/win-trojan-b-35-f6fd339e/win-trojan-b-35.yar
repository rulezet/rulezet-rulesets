rule Win_Trojan_B_35
{
strings:
	$a0 = { ec01ba14fdcd21721333d233c9b80042cd21b440ba }


condition:
	$a0
}