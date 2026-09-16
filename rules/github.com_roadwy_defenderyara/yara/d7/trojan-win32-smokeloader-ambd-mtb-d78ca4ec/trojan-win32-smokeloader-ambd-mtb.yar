rule Trojan_Win32_Smokeloader_AMBD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 55 dc 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}