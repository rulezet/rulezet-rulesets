rule Trojan_Win32_SmokeLoader_X_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 45 d0 89 45 f0 33 45 e4 31 45 fc 8b 45 fc 29 45 f8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}