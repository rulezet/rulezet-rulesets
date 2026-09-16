rule Trojan_Win32_Raccrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 ba 6b 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 66 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 90 0a 58 00 2e 00 00 00 ?? 72 00 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}