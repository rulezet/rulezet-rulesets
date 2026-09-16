rule Trojan_Win32_CobaltStrike_MA_MTB_3{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 00 33 00 2e 00 31 00 33 00 38 00 2e 00 33 00 30 00 2e 00 37 00 36 00 } 		$a_01_1 = {2f 00 6c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 2e 00 62 00 69 00 6e 00 } 		$a_01_2 = {83 bc 24 88 00 00 00 08 8d 4c 24 74 6a 00 0f 43 4c 24 78 6a 50 51 50 ff 15 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=8
 
}