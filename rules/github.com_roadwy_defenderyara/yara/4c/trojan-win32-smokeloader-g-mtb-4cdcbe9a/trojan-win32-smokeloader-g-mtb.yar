rule Trojan_Win32_Smokeloader_G_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 f4 8b 4d f8 03 c2 d3 ea 89 45 f0 03 55 d4 8b 45 f0 31 45 fc 31 55 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}