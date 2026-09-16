rule Trojan_Win32_ICLoader_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 57 4c 00 68 ?? f5 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 ?? ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}