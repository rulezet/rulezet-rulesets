rule Trojan_Win32_Neoreblamy_NIG_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 02 7d 10 8b 45 ec } 		$a_03_1 = {6a 04 58 6b c0 00 83 bc 05 ?? ff ff ff 00 6a 04 58 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}