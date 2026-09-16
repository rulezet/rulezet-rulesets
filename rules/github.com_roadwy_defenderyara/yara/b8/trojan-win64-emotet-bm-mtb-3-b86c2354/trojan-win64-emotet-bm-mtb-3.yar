rule Trojan_Win64_Emotet_BM_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c9 0f b6 0c 01 43 32 4c 0b fd 41 88 49 fd 49 83 ea 01 74 0c } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}