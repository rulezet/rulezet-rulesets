rule Backdoor_Win32_Bioazih_B_dha{
	meta:
		description = "Backdoor:Win32/Bioazih.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 74 00 68 00 65 00 72 00 65 00 3f 00 20 00 00 00 } 		$a_01_1 = {65 78 69 74 0a 00 } 		$a_03_2 = {68 fc 0f 00 00 8d 45 0c 6a 00 50 e8 ?? ?? ?? ?? 46 8d 85 ?? ?? ?? ?? 6b f6 2c 56 50 8d 45 0c 50 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}