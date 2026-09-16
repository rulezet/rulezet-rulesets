rule Trojan_BAT_AsyncRat_AYS_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 06 1c 8d ?? 00 00 01 25 16 28 ?? 00 00 06 a2 25 17 28 ?? 00 00 06 a2 25 18 28 ?? 00 00 06 a2 25 19 28 ?? 00 00 06 a2 25 1a 28 ?? 00 00 06 a2 25 1b 28 } 		$a_01_1 = {52 00 65 00 6e 00 74 00 61 00 6c 00 2e 00 56 00 69 00 65 00 77 00 2e 00 41 00 53 00 43 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}