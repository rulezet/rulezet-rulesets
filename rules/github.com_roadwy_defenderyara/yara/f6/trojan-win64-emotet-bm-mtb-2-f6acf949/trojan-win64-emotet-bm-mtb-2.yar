rule Trojan_Win64_Emotet_BM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 01 41 32 4c 3d ff 49 ff cc 88 4f ff 75 be } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}