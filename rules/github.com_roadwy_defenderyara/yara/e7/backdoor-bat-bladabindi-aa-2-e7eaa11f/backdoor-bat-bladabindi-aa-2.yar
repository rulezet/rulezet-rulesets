rule Backdoor_BAT_Bladabindi_AA__2{
	meta:
		description = "Backdoor:BAT/Bladabindi.AA!!Bladabindi,SIGNATURE_TYPE_ARHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_03_0 = {16 1f 7c 9d ?? 17 1f 27 9d ?? 18 1f 7c 9d ?? 19 1f 27 9d ?? 1a 1f 7c } 		$a_03_1 = {16 1f 5b 9d ?? 17 1f 65 9d ?? 18 1f 6e 9d ?? 19 1f 64 9d ?? 1a 1f 6f 9d ?? 1b 1f 66 9d ?? 1c 1f 5d } 		$a_03_2 = {18 1f 35 9d ?? 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45 } 		$a_03_3 = {17 1f 2e 9d ?? ?? ?? 00 00 18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? ?? ?? 00 00 1a 1f 30 9d ?? 1b 1f 45 } 		$a_03_4 = {18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45 } 		$a_03_5 = {1f 29 1f 5c 9d ?? 1f 2a 1f 52 9d ?? 1f 2b 1f 75 9d ?? 1f 2c 1f } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*10) >=31
 
}