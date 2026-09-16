rule Trojan_Win32_Raccrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {61 9b 21 1a c7 85 ?? ?? ?? ?? e7 d0 87 49 c7 85 ?? ?? ?? ?? 96 3a d0 46 c7 85 ?? ?? ?? ?? 29 5f 9d 30 c7 85 ?? ?? ?? ?? 6b 33 00 4b } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}