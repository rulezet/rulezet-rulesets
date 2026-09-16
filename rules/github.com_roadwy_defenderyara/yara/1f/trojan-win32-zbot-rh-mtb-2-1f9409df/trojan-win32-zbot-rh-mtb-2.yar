rule Trojan_Win32_Zbot_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 43 00 3a 00 5c 00 4d 00 61 00 78 00 5c 00 59 00 4c 00 49 00 51 00 63 00 5c 00 4d 00 79 00 65 00 76 00 6a 00 2e 00 76 00 62 00 70 00 } 		$a_01_1 = {45 3e d6 ba 63 25 5c 9c 2d 24 20 15 6f a3 9e b3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}