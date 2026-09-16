rule Trojan_Win32_Smokeloader_GHN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 2b f9 83 6c 24 ?? ?? 89 4c 24 ?? 89 7c 24 ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}