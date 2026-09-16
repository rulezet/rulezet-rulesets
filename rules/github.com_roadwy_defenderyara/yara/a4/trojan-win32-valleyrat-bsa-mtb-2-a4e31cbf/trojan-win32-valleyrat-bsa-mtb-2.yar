rule Trojan_Win32_ValleyRat_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/ValleyRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 eb 13 ?? ?? ?? ?? ?? 85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08 e8 97 e9 0f 00 8b f0 59 85 f6 74 de 8b c6 } 		$a_01_1 = {85 c0 74 19 ff 75 08 ff d0 59 85 c0 74 0f ff 75 08 } 		$a_03_2 = {ff 73 64 c7 45 d4 ?? ?? ?? ?? ff d6 6a 04 8d 45 d4 50 68 } 		$a_03_3 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 ?? ?? ?? ?? 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc ?? ?? ?? ?? 89 45 f8 8d 45 f0 64 a3 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*8) >=22
 
}