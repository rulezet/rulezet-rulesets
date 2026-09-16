rule Trojan_Win64_CobaltStrike_BMD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 6f 64 69 6e 67 20 74 6f 20 50 4e 47 2e 2e 2e } 		$a_01_1 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } 		$a_01_2 = {53 65 6e 64 69 6e 67 20 73 63 72 65 65 6e 73 68 6f 74 2e 2e 2e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}