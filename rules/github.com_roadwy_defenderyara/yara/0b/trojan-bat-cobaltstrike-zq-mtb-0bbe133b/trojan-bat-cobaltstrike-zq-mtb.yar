rule Trojan_BAT_CobaltStrike_ZQ_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 1f 24 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ec } 		$a_01_1 = {65 78 63 6c 75 73 69 76 65 4f 52 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}