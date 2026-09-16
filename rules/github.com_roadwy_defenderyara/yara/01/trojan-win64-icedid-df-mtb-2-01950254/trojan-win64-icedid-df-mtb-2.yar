rule Trojan_Win64_IcedID_DF_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 8d 04 12 89 c2 89 d0 c1 e0 ?? 29 d0 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 7c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}