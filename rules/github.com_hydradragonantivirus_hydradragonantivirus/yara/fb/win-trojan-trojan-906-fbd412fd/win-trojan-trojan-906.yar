rule Win_Trojan_Trojan_906
{
strings:
	$a0 = { 686572656279207765206e6f7469667920796f7520746861 }


condition:
	$a0
}