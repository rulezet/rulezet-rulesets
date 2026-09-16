rule Trojan_BAT_AsyncRat_AYR_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 08 00 00 04 11 09 7e 07 00 00 04 11 09 91 7e 09 00 00 04 11 09 7e 09 00 00 04 8e 69 5d 91 61 d2 9c 11 07 28 ?? ?? ?? 0a 00 00 11 0a 17 58 13 0a 11 0a 7e 07 00 00 04 8e 69 fe 04 13 0b 11 0b 2d a7 } 		$a_01_1 = {4e 00 6f 00 50 00 6f 00 77 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}