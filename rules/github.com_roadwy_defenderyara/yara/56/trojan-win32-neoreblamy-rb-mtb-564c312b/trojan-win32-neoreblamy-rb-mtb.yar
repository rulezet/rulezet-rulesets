rule Trojan_Win32_Neoreblamy_RB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d f8 57 8b c2 99 6a 18 5b f7 fb 89 5d e8 8b f0 8b 45 08 2b c1 89 75 ec 99 8b fe f7 fb 89 45 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}