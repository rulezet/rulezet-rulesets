rule Trojan_Win32_Predator_R_MTB_4{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_00_0 = {eb 09 8b 55 e8 03 55 f0 89 55 e8 8b 45 0c 8b 4d e8 3b 08 0f 83 fc 00 00 00 8b 55 08 8b 02 8b 4d e8 8a 14 08 88 55 ed 8b 45 08 8b 08 8b 55 e8 8a 44 0a 01 88 45 f7 8b 4d 08 8b 11 8b 45 e8 } 		$a_00_1 = {03 45 fc 8a 4d ed 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d f7 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d ef 88 08 8d 55 fc 52 e8 29 fe ff ff 83 c4 04 e9 ed fe ff ff } 		$a_02_2 = {0b c1 88 45 ?? 90 09 1b 00 c1 e1 ?? ?? ?? ?? ?? ?? ?? ?? 81 e2 } 		$a_02_3 = {0b d0 88 55 ?? 90 09 1b 00 c1 e0 ?? ?? ?? ?? ?? ?? ?? ?? 81 e1 } 		$a_02_4 = {0b ca 88 4d ?? 90 09 1a 00 c1 e2 ?? ?? ?? ?? ?? ?? ?? ?? 25 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_02_4  & 1)*5) >=17
 
}