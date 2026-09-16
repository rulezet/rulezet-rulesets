rule Trojan_BAT_AsyncRat_MD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a } 		$a_00_1 = {34 33 46 39 44 45 32 37 2d 41 34 33 30 2d 34 45 34 43 2d 38 38 37 39 2d 44 35 42 30 30 41 45 38 41 31 38 34 } 		$a_00_2 = {53 68 55 75 4a 50 51 45 59 4d 6f 46 58 51 6f 66 } 	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}