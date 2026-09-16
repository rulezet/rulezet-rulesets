rule Trojan_BAT_AsyncRat_ASY_MTB_8{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 16 11 04 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 fe 02 13 06 11 06 2d d5 } 		$a_01_1 = {52 41 54 5c 41 73 79 6e 63 52 61 74 5f 30 33 31 33 5c 72 61 74 5f 43 6c 69 65 6e 74 5c 72 61 74 5f 70 72 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 74 5f 70 72 6f 2e 70 64 62 } 		$a_01_2 = {31 00 35 00 39 00 2e 00 31 00 30 00 30 00 2e 00 31 00 33 00 2e 00 32 00 31 00 36 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=8
 
}