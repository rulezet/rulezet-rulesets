rule Trojan_BAT_LummaC_MBZR_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 62 6e 61 74 69 6f 6e 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 } 		$a_01_1 = {66 4a 68 69 73 75 41 49 55 4f 00 54 68 72 53 67 74 72 6a 79 74 00 52 65 6d 6f 74 65 4f 62 6a 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}