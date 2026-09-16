rule Trojan_Win64_Rozena_NR_MTB_6{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 20 48 8d 05 7d 71 1c 00 e8 ?? ?? ?? ?? 48 8b 4c 24 10 48 89 08 48 8b 4c 24 20 48 8b 11 48 89 50 10 48 89 01 } 		$a_01_1 = {48 8d 15 1d 7b 0c 00 48 89 c6 48 8b 44 24 40 48 89 df 48 89 f3 49 89 c8 48 89 f9 41 ff d0 48 8b 4c 24 40 48 8d 14 49 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}