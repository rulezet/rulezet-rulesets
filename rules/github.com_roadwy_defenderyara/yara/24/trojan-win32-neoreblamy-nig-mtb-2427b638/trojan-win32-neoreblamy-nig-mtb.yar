rule Trojan_Win32_Neoreblamy_NIG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 10 8b 45 dc } 		$a_01_1 = {eb 07 8b 45 e8 48 89 45 e8 83 7d e8 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}