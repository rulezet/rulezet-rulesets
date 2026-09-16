rule Trojan_Win32_Neoreblamy_GPJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {4e 6a 68 66 67 79 78 72 65 74 46 67 5a 78 4f 61 66 4f 4b 65 66 } 		$a_81_1 = {45 66 61 45 41 63 66 61 72 4a 54 48 70 } 		$a_81_2 = {64 62 7a 6e 49 53 6a 68 61 74 78 42 46 4d 4f } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}