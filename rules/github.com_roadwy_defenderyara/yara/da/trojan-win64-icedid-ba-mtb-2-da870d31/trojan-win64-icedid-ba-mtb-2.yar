rule Trojan_Win64_IcedID_BA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 0f b7 4c 24 ?? 3a d2 74 ?? 66 89 44 24 ?? 48 ?? ?? ?? ?? ?? ?? ?? 66 3b c9 74 ?? 33 c8 8b c1 66 3b c9 74 } 		$a_03_1 = {8b c0 3a ff 74 ?? 8b 44 24 ?? f7 b4 24 ?? ?? ?? ?? 66 3b c9 74 ?? 89 84 24 ?? ?? ?? ?? 33 d2 66 3b f6 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}