rule Trojan_BAT_FormBook_SJ_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.SJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 11 09 02 6f 34 00 00 0a fe 04 16 fe 01 13 16 11 16 2c 05 38 b1 02 00 00 11 0a 02 6f 35 00 00 0a fe 04 16 fe 01 13 17 11 17 2c 05 38 8a 02 00 00 16 13 0b 11 07 75 11 00 00 02 14 fe 03 13 18 11 18 2c 10 } 		$a_01_1 = {13 0e 11 08 11 0f 6f 7a 00 00 06 13 0f 11 0d 1b 62 11 0d 19 63 60 d2 13 0d 11 0d 1b 63 11 0d 19 62 60 d2 13 0d 11 0e 20 f3 00 00 00 58 20 ff 00 00 00 5f d2 13 0e 11 0e 20 f3 00 00 00 59 20 ff 00 00 00 5f d2 13 0e 11 0f 20 c8 00 00 00 61 d2 13 0f 11 0f 20 c8 00 00 00 61 d2 13 0f 11 07 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}