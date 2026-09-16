rule Trojan_Win32_SmokeLoader_DE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}