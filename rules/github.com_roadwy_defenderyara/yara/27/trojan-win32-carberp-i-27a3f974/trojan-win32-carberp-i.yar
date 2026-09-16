rule Trojan_Win32_Carberp_I{
	meta:
		description = "Trojan:Win32/Carberp.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 45 0a 03 00 66 c7 45 08 01 00 90 09 14 00 eb 25 (6a 04 8d 45 08|8d 45 08 6a 04) 50 68 80 00 00 00 68 ff ff 00 00 57 66 } 		$a_03_1 = {c6 45 f8 63 [0-08] 66 c7 45 fb 03 00 } 		$a_01_2 = {66 89 75 f7 c6 45 f4 73 66 89 45 f5 } 		$a_03_3 = {66 89 95 ab f9 ff ff c6 85 a8 f9 ff ff 73 66 8b 45 ?? 66 89 85 a9 f9 ff ff } 		$a_00_4 = {73 26 73 74 61 74 70 61 73 73 3d 25 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=2
 
}