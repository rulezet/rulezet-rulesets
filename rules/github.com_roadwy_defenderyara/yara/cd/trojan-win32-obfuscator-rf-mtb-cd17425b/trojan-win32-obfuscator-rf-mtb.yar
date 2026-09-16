rule Trojan_Win32_Obfuscator_RF_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 44 34 50 81 e1 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 ?? 8a 54 14 14 32 c2 88 03 43 4d 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}