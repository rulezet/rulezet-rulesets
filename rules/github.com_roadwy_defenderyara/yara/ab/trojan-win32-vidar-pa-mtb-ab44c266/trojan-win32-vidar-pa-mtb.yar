rule Trojan_Win32_Vidar_PA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } 		$a_01_1 = {8b 45 88 8d 0c 06 33 d2 8b c6 f7 75 84 8a 04 3a 8b 55 80 32 04 0a 46 88 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}