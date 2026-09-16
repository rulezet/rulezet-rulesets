rule Win_Trojan_Fis_2
{
strings:
	$a0 = { 882488440183c60259e2e9b9e00283e950be000183c650518a0e0f018a04d2c088044659e2f1 }


condition:
	$a0
}