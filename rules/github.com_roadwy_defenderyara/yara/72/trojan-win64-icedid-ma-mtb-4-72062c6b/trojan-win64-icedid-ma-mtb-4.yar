rule Trojan_Win64_IcedID_MA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 48 89 74 71 3e 4b 89 44 24 18 55 02 6f 59 48 8b ec 48 83 b9 4e 47 8b f9 4d 8b f1 ec 31 11 5a } 		$a_01_1 = {30 48 3b f9 27 25 84 42 40 48 03 c1 1d 15 f7 72 05 48 8b 12 be f0 47 85 c9 0f 84 f4 55 2e 0f 4c } 		$a_01_2 = {8b c0 4c 63 87 66 96 83 e2 03 48 03 97 ad ef 03 48 2b c2 48 36 e6 4e 0f b6 04 1a 44 5a 98 4b 0d } 		$a_81_3 = {69 6e 69 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_81_3  & 1)*1) >=10
 
}