rule Trojan_Win32_Smokeloader_CZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 4d ?? 03 c3 30 08 83 7d ?? 0f 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}