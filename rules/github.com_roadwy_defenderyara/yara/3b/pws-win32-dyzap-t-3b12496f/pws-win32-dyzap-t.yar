rule PWS_Win32_Dyzap_T{
	meta:
		description = "PWS:Win32/Dyzap.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 b8 61 00 00 00 b9 52 00 00 00 57 66 89 45 f0 66 89 4d ec ff 15 } 		$a_03_1 = {c6 45 f3 75 c6 45 f7 6a ff 15 ?? ?? ?? ?? 85 c0 74 11 } 		$a_01_2 = {ff d0 6a 04 68 00 30 00 00 68 00 00 02 00 6a 00 89 44 24 34 ff 54 24 28 8b f8 } 		$a_03_3 = {c6 45 f0 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4d 08 51 6a 00 68 08 04 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}