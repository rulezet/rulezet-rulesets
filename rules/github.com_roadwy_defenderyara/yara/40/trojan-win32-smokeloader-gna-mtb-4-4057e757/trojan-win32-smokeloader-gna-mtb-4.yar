rule Trojan_Win32_Smokeloader_GNA_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {62 d4 ec 26 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 46 47 2e 63 81 44 24 ?? d0 50 3e 7e 81 6c 24 ?? 74 f6 20 40 81 44 24 ?? 6d 8d f3 1b 81 44 24 ?? 1a 8d 4c 3c 81 6c 24 ?? a7 1e 7a 2c } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}