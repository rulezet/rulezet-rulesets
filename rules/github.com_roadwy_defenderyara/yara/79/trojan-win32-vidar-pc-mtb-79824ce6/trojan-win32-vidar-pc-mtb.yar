rule Trojan_Win32_Vidar_PC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 88 8d 0c 07 33 d2 8b c7 f7 f3 8b 85 ?? ?? ?? ?? 56 8a 04 02 8b 55 84 32 04 0a 88 01 } 		$a_03_1 = {2b c1 89 45 ?? 8b 45 ?? 8d 0c ?? 33 d2 8b c3 f7 75 ?? 8b 85 ?? ?? ?? ?? 57 8a 04 02 8b 55 84 32 04 0a 88 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}