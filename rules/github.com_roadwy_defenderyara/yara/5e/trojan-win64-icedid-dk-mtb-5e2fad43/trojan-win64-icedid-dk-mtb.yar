rule Trojan_Win64_IcedID_DK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 } 		$a_03_1 = {8b 0c 24 48 8b 54 24 ?? 0f b6 0c 0a 33 4c 24 ?? 81 e1 ?? ?? ?? ?? 8b c9 48 8d 15 ?? ?? ?? ?? 33 04 8a 89 44 24 ?? eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}