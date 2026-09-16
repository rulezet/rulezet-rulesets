rule Trojan_Win32_Neoreblamy_NFK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 04 7d 10 8b 45 e8 } 		$a_01_1 = {7d 7b 83 65 b8 00 eb 07 8b 45 b8 40 89 45 b8 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}