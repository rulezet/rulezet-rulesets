rule TrojanDownloader_Win32_Upatre_H_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {a3 04 d9 40 00 66 c7 85 2c ff ff ff 6b 00 8a 8d 34 ff ff ff 88 8d 4d ff ff ff c6 45 a8 65 66 c7 85 2e ff ff ff 65 00 c6 45 ae 45 8a 95 2e ff ff ff 88 95 52 ff ff ff 66 c7 85 3a ff ff ff 32 00 } 		$a_01_1 = {c6 85 4c ff ff ff 47 c6 85 4d ff ff ff 0d c6 85 4e ff ff ff 74 c6 85 4f ff ff ff 46 c6 85 50 ff ff ff 69 c6 85 51 ff ff ff 6c c6 85 52 ff ff ff 70 c6 85 53 ff ff ff 41 c6 85 54 ff ff ff 74 c6 85 55 ff ff ff 74 c6 85 56 ff ff ff 72 } 		$a_03_2 = {ff ff ff 6b 8a 8d ?? ff ff ff 88 8d ?? ff ff ff c6 45 a8 65 ?? ?? ?? ff ff ff 65 c6 45 ae 45 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? ff ff ff 32 } 		$a_03_3 = {c6 45 a8 65 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? 2e ff ff ff 65 00 c6 45 ae 45 8a 85 ?? ff ff ff 88 85 ?? ff ff ff } 		$a_03_4 = {c6 45 bc 65 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? ?? ff ff ff 65 00 c6 45 ?? 45 8a 85 ?? ff ff ff 88 85 ?? ff ff ff } 		$a_03_5 = {c6 45 bc 65 c6 85 79 ff ff ff 65 c6 45 c2 45 c6 85 7e ff ff ff 65 68 ?? ?? 40 00 ff 15 } 		$a_01_6 = {c6 45 86 70 c6 45 87 41 c6 45 88 74 c6 45 89 74 c6 45 8a 72 c6 45 8b 69 c6 45 8c 62 c6 45 8d 75 c6 45 8e 74 c6 45 8f 65 c6 45 90 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}