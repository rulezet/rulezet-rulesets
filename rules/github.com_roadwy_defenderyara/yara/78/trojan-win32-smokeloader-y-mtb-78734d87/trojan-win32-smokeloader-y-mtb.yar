rule Trojan_Win32_Smokeloader_Y_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f0 33 45 ?? 31 45 ?? 8b 45 fc 29 45 f8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}