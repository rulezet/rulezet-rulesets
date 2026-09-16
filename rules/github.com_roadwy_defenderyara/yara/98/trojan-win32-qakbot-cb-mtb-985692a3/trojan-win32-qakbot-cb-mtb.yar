rule Trojan_Win32_Qakbot_CB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 d9 56 29 cb 8b 46 08 03 46 10 01 4e 10 89 c6 89 ca c1 e9 02 fc } 		$a_81_1 = {54 64 72 68 79 6d 77 34 6f 69 35 6a } 		$a_81_2 = {35 35 36 36 36 6e 30 6a 75 6d 62 34 39 35 36 6a 38 68 79 75 62 74 6e 76 65 6a 72 74 67 65 6f 72 68 77 72 79 39 35 38 75 36 6a 39 79 35 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}