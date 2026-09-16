rule Trojan_BAT_PureCrypter_APU_MTB_2{
	meta:
		description = "Trojan:BAT/PureCrypter.APU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da } 		$a_01_1 = {31 00 30 00 33 00 2e 00 32 00 32 00 38 00 2e 00 33 00 37 00 2e 00 35 00 31 00 2f 00 48 00 4f 00 53 00 54 00 31 00 2f 00 52 00 65 00 79 00 74 00 6e 00 70 00 67 00 2e 00 64 00 61 00 74 00 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}