rule Trojan_BAT_Bulz_NB_MTB_3{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 24 00 00 0a 73 1b 00 00 0a 0c 08 07 6f 25 00 00 0a 25 26 1f 4c 28 18 00 00 06 73 26 00 00 0a 0d 09 02 1f 50 28 18 00 00 06 02 8e 69 1f 54 28 18 00 00 06 59 6f 1d 00 00 0a } 		$a_01_1 = {4c 6f 61 64 65 72 20 43 53 47 4f 20 76 32 2d 20 43 68 65 61 74 73 54 44 4d 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}