rule Trojan_BAT_RemcosRAT_SJ_MTB_2{
	meta:
		description = "Trojan:BAT/RemcosRAT.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 02 11 05 11 06 6f 3a 00 00 0a 13 07 06 7b 8e 00 00 04 6f 3b 00 00 0a 03 fe 04 13 08 11 08 2c 13 06 7b 8e 00 00 04 12 07 28 3c 00 00 0a 6f 3d 00 00 0a 00 06 7b 8e 00 00 04 6f 3b 00 00 0a 03 fe 04 13 09 11 09 2c 13 06 7b 8e 00 00 04 12 07 28 3e 00 00 0a 6f 3d 00 00 0a } 		$a_81_1 = {52 65 67 69 73 74 72 79 43 6c 65 61 6e 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}