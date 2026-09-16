rule Trojan_BAT_AsyncRat_ASA_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 07 06 28 ?? 00 00 0a 26 03 17 18 16 73 ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a de 0a 07 2c 06 07 6f ?? 00 00 0a dc 03 03 28 } 		$a_01_1 = {0b 16 0c 2b 13 07 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}