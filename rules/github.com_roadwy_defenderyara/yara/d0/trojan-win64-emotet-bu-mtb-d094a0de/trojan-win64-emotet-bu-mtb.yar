rule Trojan_Win64_Emotet_BU_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 03 d1 41 ff c1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 13 ?? 41 88 4a ?? 48 ff cb 74 09 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}