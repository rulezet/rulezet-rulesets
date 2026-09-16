rule Trojan_Win64_IcedID_MD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 01 c0 89 c2 c1 e2 ?? 01 d0 29 c1 89 c8 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 39 c2 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}