rule Trojan_Win32_Smokeloader_F_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 c4 04 10 00 00 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}