rule Trojan_Win32_Smokeloader_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 cc 33 45 ec 33 c8 2b f1 83 6d e0 ?? 89 4d fc 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}