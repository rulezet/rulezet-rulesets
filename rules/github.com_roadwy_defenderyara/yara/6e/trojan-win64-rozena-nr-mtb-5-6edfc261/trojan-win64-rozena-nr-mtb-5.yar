rule Trojan_Win64_Rozena_NR_MTB_5{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 35 7b e0 55 00 65 48 8b 04 25 30 00 00 00 48 8b 58 08 31 c0 f0 48 0f b1 5d 00 74 ?? 48 39 c3 74 ?? b9 e8 03 00 00 } 		$a_03_1 = {8d 4b 01 48 63 c9 48 c1 e1 03 e8 ?? ?? ?? ?? 4c 8b 35 d0 bd 55 00 49 89 c5 44 39 e3 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}