rule Trojan_BAT_AsyncRat_AMMH_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 fe 0c 01 00 6f ?? 00 00 0a 20 01 00 00 00 73 ?? 00 00 0a 25 fe 0c 00 00 20 ?? 00 00 00 fe 0c 00 00 8e 69 6f ?? 00 00 0a 25 6f ?? 00 00 0a fe 0c 02 00 6f ?? 00 00 0a fe 0e 00 00 fe 0c 02 00 6f ?? 00 00 0a 6f ?? 00 00 0a 20 ?? ff ff ff 28 ?? 00 00 0a fe 0e 03 00 } 		$a_80_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_80_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_80_3 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } 	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}