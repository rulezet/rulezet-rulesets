rule Trojan_BAT_Disstl_ADI_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 80 00 00 00 6f 57 00 00 0a 00 06 20 00 01 00 00 6f 58 00 00 0a 00 06 17 6f 59 00 00 0a 00 06 18 6f 5a 00 00 0a 00 06 28 5b 00 00 0a 03 6f 5c 00 00 0a 6f 5d 00 00 0a 00 06 28 5b 00 00 0a 04 6f 5c 00 00 0a 6f 5e 00 00 0a 00 06 06 6f 5f 00 00 0a 06 6f 60 00 00 0a 6f 68 00 00 0a 0b 7e 69 00 00 0a 0c 02 28 } 		$a_01_1 = {46 00 75 00 63 00 6b 00 65 00 64 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}