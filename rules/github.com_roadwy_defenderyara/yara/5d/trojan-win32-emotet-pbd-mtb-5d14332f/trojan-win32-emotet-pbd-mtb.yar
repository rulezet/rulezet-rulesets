rule Trojan_Win32_Emotet_PBD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_03_1 = {2b d7 03 54 24 ?? 03 54 24 ?? 03 54 24 ?? 0f b6 14 02 8b 44 24 ?? 30 54 28 ?? 3b ac 24 [0-04] 0f 82 } 		$a_03_2 = {03 d7 03 54 24 ?? 03 54 24 ?? 0f b6 14 02 8b 44 24 ?? 30 54 28 ?? 3b 6c 24 ?? 0f 82 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=3
 
}