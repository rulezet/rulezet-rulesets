rule Trojan_BAT_Jalapeno_PGJ_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 12 01 28 ?? 00 00 06 02 06 07 28 ?? 00 00 06 51 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 06 51 2a } 		$a_80_1 = {6a 59 44 34 71 54 37 39 69 6a 57 62 63 50 6f 6b 78 6c 58 37 6b 69 48 64 7a 72 2b 6d 71 54 64 50 74 41 4f 52 6b 51 65 30 34 4d 52 6c 76 4d 46 52 30 59 55 67 49 37 51 44 6b 5a 45 48 74 4f 44 45 } 	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}