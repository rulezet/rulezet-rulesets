rule Trojan_Win32_Emotet_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b c7 33 f6 89 74 24 14 8d 2c 08 8b 0d ?? ?? ?? ?? 8b f9 8b dd 0f af f9 0f af da 0f af fa } 		$a_01_1 = {45 72 4a 49 5a 77 51 25 42 34 58 5f 23 2a 54 55 75 55 33 32 76 78 28 63 39 5f 40 38 2a 43 21 42 69 37 64 58 37 6f } 	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}