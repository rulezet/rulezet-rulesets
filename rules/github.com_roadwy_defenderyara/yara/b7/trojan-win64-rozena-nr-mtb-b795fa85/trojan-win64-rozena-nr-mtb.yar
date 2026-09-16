rule Trojan_Win64_Rozena_NR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d da fd ff ff 48 89 02 e8 da 40 00 00 e8 4d 36 00 00 48 63 1d ?? ?? ?? ?? 8d 4b 01 48 63 c9 } 		$a_03_1 = {48 c1 e1 03 e8 6f 41 00 00 4c 8b 35 ?? ?? ?? ?? 49 89 c5 44 39 e3 7e 2b 4b 8b 0c e6 e8 6f 41 00 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}