rule Win_Trojan_VECN1401_1
{
strings:
	$a0 = { fb8ed8832e130403cd12b106d3e02d10008ec0bb0001b80302b90300b60080fa807405b9 }


condition:
	$a0
}