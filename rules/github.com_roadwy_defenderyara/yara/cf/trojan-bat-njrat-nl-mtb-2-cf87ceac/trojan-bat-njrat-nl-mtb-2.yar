rule Trojan_BAT_NjRat_NL_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 53 00 fe 0c 6d 00 fe 0c 6d 00 1f 17 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 77 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1d 64 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 55 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1e 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 53 00 58 fe 0e 6d 00 fe 0c 55 00 1b 62 fe 0c 77 00 58 fe 0c 55 00 61 fe 0c 6d 00 59 fe 0e 6d 00 fe 0c 6d 00 76 6c 6d 58 13 41 } 		$a_01_1 = {62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 1c 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1d 64 61 fe 0e 26 00 fe 0c 26 00 fe 0c 23 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1e 62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 13 00 58 fe 0e 26 00 fe 0c 23 00 1b 62 fe 0c 1c 00 58 fe 0c 23 00 61 fe 0c 26 00 59 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}