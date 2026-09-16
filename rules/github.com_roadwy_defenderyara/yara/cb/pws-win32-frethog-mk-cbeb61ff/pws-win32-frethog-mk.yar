rule PWS_Win32_Frethog_MK{
	meta:
		description = "PWS:Win32/Frethog.MK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 63 f3 ab 90 09 13 00 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 62 c6 85 } 		$a_01_1 = {6a 00 6a 77 54 50 ff 55 40 ff d0 } 		$a_01_2 = {73 76 63 68 6f 73 74 2e 64 6c 6c 00 41 52 00 47 65 74 56 65 72 00 77 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}