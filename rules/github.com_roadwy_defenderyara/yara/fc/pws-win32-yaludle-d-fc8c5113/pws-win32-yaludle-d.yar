rule PWS_Win32_Yaludle_D{
	meta:
		description = "PWS:Win32/Yaludle.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 41 01 41 84 c0 75 f4 53 8a 19 33 c0 3a da 0f 95 c0 48 5b 23 c1 c3 } 		$a_03_1 = {85 c0 74 16 2d ?? ?? ?? ?? b9 ?? 00 00 00 83 c0 ?? 99 f7 f9 8a 9a ?? ?? ?? ?? 88 1c 2e 8a 46 01 47 46 84 c0 75 c2 } 		$a_01_2 = {68 4d a0 07 6c 56 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}