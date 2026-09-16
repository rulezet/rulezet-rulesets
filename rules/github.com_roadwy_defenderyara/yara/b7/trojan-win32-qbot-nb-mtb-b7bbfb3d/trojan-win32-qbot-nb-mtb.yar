rule Trojan_Win32_Qbot_NB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {33 55 f0 89 55 f0 8b 45 ec 8b 4d f8 d3 f8 83 f0 04 89 45 ec 8b 55 f4 03 55 08 8b 4d 08 d3 e2 8b 4d 08 d3 fa 8b 4d f8 d3 fa 8b 4d f8 d3 e2 8b 4d 08 d3 } 		$a_81_1 = {72 6f 6c 6c 69 63 68 65 } 		$a_81_2 = {74 72 69 6f 62 6f 6c } 		$a_81_3 = {44 6c 6c 5c 6f 75 74 2e 70 64 62 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}