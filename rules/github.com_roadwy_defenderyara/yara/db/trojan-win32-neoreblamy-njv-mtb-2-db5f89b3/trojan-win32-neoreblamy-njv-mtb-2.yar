rule Trojan_Win32_Neoreblamy_NJV_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 58 6b c0 00 8b 84 05 b4 fe ff ff 40 6a 04 59 6b c9 00 } 		$a_01_1 = {eb 07 8b 45 b8 40 89 45 b8 83 7d b8 03 7d 10 8b 45 b8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}