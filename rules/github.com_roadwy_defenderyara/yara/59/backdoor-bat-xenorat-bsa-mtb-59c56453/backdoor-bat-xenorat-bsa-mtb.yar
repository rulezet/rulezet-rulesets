rule Backdoor_BAT_XenoRat_BSA_MTB{
	meta:
		description = "Backdoor:BAT/XenoRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 65 6e 6f 20 72 61 74 20 63 6c 69 65 6e 74 } 		$a_01_1 = {1b 30 06 00 84 0b 00 00 10 00 00 11 12 00 14 7d 04 00 00 04 14 0b 72 64 05 00 70 0c 08 18 28 32 00 00 0a 28 33 00 00 0a 16 28 34 00 00 0a 26 21 00 60 40 00 00 00 00 00 e0 0d 20 b7 50 00 00 13 04 11 04 8d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}