rule PWS_Win32_Lolyda_BF_2{
	meta:
		description = "PWS:Win32/Lolyda.BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 43 01 9c c6 43 02 e8 c6 43 07 9d c6 43 08 61 } 		$a_03_1 = {73 20 80 b9 ?? ?? ?? ?? 5f 74 10 41 56 89 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 eb dd c6 81 ?? ?? ?? ?? 40 } 		$a_03_2 = {6a 0e 83 c3 36 51 50 66 c7 45 ?? 42 4d 89 5d ?? 66 89 7d ?? 66 89 7d ?? c7 45 ?? 36 00 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}