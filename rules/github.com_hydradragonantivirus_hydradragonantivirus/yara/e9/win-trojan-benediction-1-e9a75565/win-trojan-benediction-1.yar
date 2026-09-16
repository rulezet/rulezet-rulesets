rule Win_Trojan_Benediction_1
{
strings:
	$a0 = { bb0301ba????3107434039d375f8c6060001??c6060101??c6060201??31c031db31d2e9 }


condition:
	$a0
}