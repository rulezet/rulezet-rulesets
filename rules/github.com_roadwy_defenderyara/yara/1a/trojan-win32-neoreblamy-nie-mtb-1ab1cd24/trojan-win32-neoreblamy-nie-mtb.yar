rule Trojan_Win32_Neoreblamy_NIE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 02 7d 10 8b 45 dc } 		$a_03_1 = {6a 04 59 6b c9 00 3b 84 0d ?? ?? ff ff 7f 0c } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}