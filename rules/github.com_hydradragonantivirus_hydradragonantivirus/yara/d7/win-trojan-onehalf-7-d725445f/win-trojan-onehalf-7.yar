rule Win_Trojan_OneHalf_7
{
strings:
	$a0 = { 2c014c7a0bb3d6ca32563326759e446f6243931ce986e970fd613a502532f5a9b8701c9506ccec3646fe0d7f76d45a2b }


condition:
	$a0
}