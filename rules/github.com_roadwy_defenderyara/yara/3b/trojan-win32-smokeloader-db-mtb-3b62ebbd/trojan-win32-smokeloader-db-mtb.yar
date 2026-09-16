rule Trojan_Win32_SmokeLoader_DB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 55 e8 01 10 8b 45 d8 03 45 ac 03 45 e8 8b 55 ec 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}