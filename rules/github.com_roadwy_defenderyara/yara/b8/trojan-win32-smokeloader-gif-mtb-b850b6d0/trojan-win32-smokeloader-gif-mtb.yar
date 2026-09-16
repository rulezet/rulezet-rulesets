rule Trojan_Win32_Smokeloader_GIF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 45 c4 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c7 30 08 83 fb 0f 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}