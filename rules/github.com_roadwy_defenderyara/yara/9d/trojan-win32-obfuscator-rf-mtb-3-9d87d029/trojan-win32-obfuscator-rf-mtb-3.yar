rule Trojan_Win32_Obfuscator_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Obfuscator.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 fc 33 c0 89 45 ec 83 7d ec 00 ?? ?? 8b 45 ec 83 e0 ?? 85 c0 ?? ?? 8b 45 ec 8a 80 ?? ?? ?? ?? 34 d9 8b 55 fc 03 55 ec 88 02 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}