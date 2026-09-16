rule Trojan_Win32_Obfuscator_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 14 8d 5e a9 8b 44 24 24 03 d9 05 ?? ?? ?? ?? 8b f3 2b f7 a3 ?? ?? ?? ?? 89 02 83 ee 07 83 c2 04 ff 4c 24 18 89 54 24 14 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}