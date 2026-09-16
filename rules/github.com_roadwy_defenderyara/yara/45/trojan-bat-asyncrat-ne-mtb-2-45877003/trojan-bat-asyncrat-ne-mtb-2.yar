rule Trojan_BAT_AsyncRat_NE_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 58 0b 72 ?? 00 00 70 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a } 		$a_01_1 = {46 6c 61 70 70 79 5f 42 69 72 64 5f 57 69 6e 64 6f 77 73 5f 46 6f 72 6d } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}