rule Trojan_Win32_Zloader_C_ibt{
	meta:
		description = "Trojan:Win32/Zloader.C!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 89 c1 81 f1 f2 00 00 00 89 ca 0f af d0 31 d1 0f af ca 29 d1 81 f1 ae 02 00 00 8d 91 44 ff ff ff 89 d6 0f af f1 09 f2 0f be d2 01 f2 89 d6 29 ce 21 ce 35 77 d8 dd 9d 01 f1 0f af ca 0f af ce 0f af c9 69 c9 d0 01 00 00 } 		$a_03_1 = {8b 5d 0c b9 c1 de 31 35 89 d8 89 de f7 e1 c1 ea 07 69 c2 68 02 00 00 29 c6 8b 0c b5 ?? ?? ?? ?? 85 c9 74 2f 31 c0 90 90 90 90 [0-10] 39 d9 0f 84 96 00 00 00 81 fe 66 02 00 00 8d 76 01 0f 4f f0 8b 0c b5 ?? ?? ?? ?? 85 c9 75 e1 } 		$a_03_2 = {53 57 56 81 ec ?? ?? 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? be ff ff ff ff e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? 00 00 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}