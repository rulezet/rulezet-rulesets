rule Trojan_Win64_CobaltStrike_SPL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 33 62 65 66 34 37 39 2e 74 6d 70 } 		$a_01_1 = {52 65 6c 65 61 73 65 5c 53 65 74 75 70 45 6e 67 69 6e 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}