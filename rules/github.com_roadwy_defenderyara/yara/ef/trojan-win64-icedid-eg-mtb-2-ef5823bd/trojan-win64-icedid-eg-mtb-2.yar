rule Trojan_Win64_IcedID_EG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 ?? 29 c1 89 ca 48 63 d2 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}