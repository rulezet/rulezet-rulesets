rule Trojan_Win32_SmokeLoader_DD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 d8 03 45 ac 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d b0 8b 45 ec 8b 55 b0 31 10 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}