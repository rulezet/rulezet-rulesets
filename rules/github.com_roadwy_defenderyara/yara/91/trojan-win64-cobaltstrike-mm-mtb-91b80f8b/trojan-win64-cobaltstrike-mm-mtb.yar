rule Trojan_Win64_CobaltStrike_MM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 75 64 53 6f 6c 76 65 72 2e 70 64 62 } 		$a_01_1 = {43 00 61 00 70 00 74 00 75 00 72 00 65 00 20 00 64 00 65 00 76 00 69 00 63 00 65 00 20 00 69 00 6e 00 66 00 6f 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}