rule Backdoor_Win32_Bioazih_A_dha_2{
	meta:
		description = "Backdoor:Win32/Bioazih.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 08 80 f3 04 88 1c 08 40 3b c2 7c f2 } 		$a_01_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 74 00 61 00 73 00 6b 00 73 00 5c 00 63 00 6f 00 6e 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {50 61 73 73 3a 25 73 20 48 6f 73 74 6e 61 6d 65 3a 25 73 20 49 70 3a 25 73 20 4f 73 3a 25 73 20 50 72 6f 78 79 3a 25 73 20 56 6d 3a 25 73 20 50 72 6f 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}