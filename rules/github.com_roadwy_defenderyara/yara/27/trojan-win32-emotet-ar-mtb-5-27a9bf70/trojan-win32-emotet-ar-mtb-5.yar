rule Trojan_Win32_Emotet_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10 } 		$a_01_1 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 31 40 88 50 ff 89 44 24 24 ff 4c 24 10 } 		$a_01_2 = {8b 44 24 10 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 28 8b 44 24 24 83 c3 01 81 fb e1 18 00 00 8a 14 02 88 16 } 		$a_01_3 = {8a 14 0f 8a 04 0e 88 14 0e 88 04 0f 0f b6 14 0e 0f b6 c0 03 c2 33 d2 f7 f5 0f b6 04 0a 8b 54 24 14 32 44 1a ff 83 6c 24 20 01 88 43 ff } 		$a_81_4 = {6c 68 78 58 66 59 39 6d 49 72 44 5a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1) >=2
 
}