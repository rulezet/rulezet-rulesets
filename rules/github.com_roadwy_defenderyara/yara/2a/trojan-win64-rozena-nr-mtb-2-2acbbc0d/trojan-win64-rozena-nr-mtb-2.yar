rule Trojan_Win64_Rozena_NR_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 24 48 8b 05 c9 e6 10 00 48 83 f8 00 74 06 48 83 38 00 75 11 48 8d 05 8e 4d 00 00 ff d0 } 		$a_01_1 = {e8 7d ff ff ff 48 8b 0d e6 3c 15 00 65 48 8b 09 48 8b 7c 24 08 48 8b 77 08 48 2b 34 24 48 89 39 48 89 f4 89 44 24 20 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}