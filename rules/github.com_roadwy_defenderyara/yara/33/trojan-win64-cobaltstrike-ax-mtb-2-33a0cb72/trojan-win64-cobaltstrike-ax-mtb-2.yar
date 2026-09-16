rule Trojan_Win64_CobaltStrike_AX_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 65 61 63 6f 6e 5f 73 65 74 5f 4d 65 6d 6f 72 79 5f 61 74 74 72 69 62 75 74 65 73 } 		$a_01_1 = {4e 63 34 38 38 33 65 34 4e 30 65 38 63 38 30 30 30 30 30 30 34 31 35 31 34 31 35 30 35 32 35 31 35 36 34 38 33 31 64 32 36 35 34 38 38 62 35 32 36 30 34 38 38 62 35 32 31 38 34 38 38 62 35 32 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}