rule Trojan_Win32_Zbot_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 52 4a 5a 45 42 55 4d 4a 47 43 48 4e 4c 51 58 4f 50 4b 4b 51 57 44 4f 4b 44 } 		$a_01_1 = {42 47 42 41 51 46 58 51 5a } 		$a_01_2 = {53 4f 57 51 4b 46 54 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}