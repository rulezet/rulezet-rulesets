rule Trojan_Win64_Emotet_BM_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c0 ff c6 45 8a 04 10 45 32 04 1f 44 88 03 48 ff c3 48 ff cf 75 c7 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}