rule Trojan_Win32_Cridex_AR_MTB_8{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 81 c1 08 e8 02 01 89 0a 8b 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 ca } 		$a_02_1 = {8b 7c 24 2c 81 c2 78 41 0c 01 8b 74 24 1c 83 c6 3b 89 54 24 18 03 f0 89 15 ?? ?? ?? ?? 89 17 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}