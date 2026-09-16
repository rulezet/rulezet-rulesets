rule Trojan_BAT_LummaC_MBZR_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2b 03 17 2b 00 3a ?? 00 00 00 06 6f ?? 03 00 0a 11 06 6f ?? 03 00 0a 16 73 58 03 00 0a 13 0d 11 0d 11 07 28 4f 18 00 06 de 14 11 0d } 		$a_03_1 = {2b 21 02 7b ?? 05 00 04 07 06 6f ?? ?? ?? 0a 20 ?? 1d 1b be 20 ?? 35 de fb 58 20 ?? 6b 14 ed 61 6a 61 9f 07 20 a3 0c 4d c8 } 		$a_01_2 = {52 70 79 6f 69 64 70 66 2e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}