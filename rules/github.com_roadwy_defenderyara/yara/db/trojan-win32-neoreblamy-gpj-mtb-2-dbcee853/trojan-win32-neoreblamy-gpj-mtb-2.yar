rule Trojan_Win32_Neoreblamy_GPJ_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {71 5a 77 57 6b 46 46 6e 69 6a 6e 6d 67 4c 71 4c 4c 67 72 6b 63 76 48 } 		$a_81_1 = {53 4b 66 43 4a 78 45 43 62 65 45 6b 56 63 52 } 		$a_81_2 = {64 55 58 48 48 6f 5a 65 74 4d 65 6f 43 6d 6a 6b 76 56 75 73 69 6c 64 65 4c } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}