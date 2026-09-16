rule Trojan_Win64_IcedID_ZB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 d1 fa 8b c2 c1 e8 ?? 03 d0 8d 04 92 3b c8 74 05 01 7d ?? eb ?? ff 4d ?? 8b 4d ?? 41 ?? ?? f7 e9 8b c2 c1 e8 ?? 03 d0 8d 04 52 3b c8 74 } 		$a_00_1 = {44 6c 6c 4d 61 69 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}