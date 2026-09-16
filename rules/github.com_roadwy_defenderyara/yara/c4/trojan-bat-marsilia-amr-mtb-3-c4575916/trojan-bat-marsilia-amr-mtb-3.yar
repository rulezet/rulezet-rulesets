rule Trojan_BAT_Marsilia_AMR_MTB_3{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 0b 16 0c 2b 1a 07 08 91 0d 06 72 70 0a 00 70 09 8c 6f 00 00 01 6f ?? 00 00 0a 26 08 17 58 0c 08 07 8e 69 } 		$a_01_1 = {74 65 73 74 5f 61 69 6d 62 6f 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}