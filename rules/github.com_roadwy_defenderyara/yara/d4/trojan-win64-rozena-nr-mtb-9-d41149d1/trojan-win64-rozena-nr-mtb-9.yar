rule Trojan_Win64_Rozena_NR_MTB_9{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 6b 22 00 00 ff 15 95 20 00 00 b9 ?? ?? 00 00 66 89 bd ?? ?? 00 00 ff 15 7b 20 00 00 44 8d 47 0e 48 8b cb 48 8d 95 ?? ?? 00 00 66 89 85 ?? ?? 00 00 ff 15 80 20 00 00 } 		$a_03_1 = {ff 15 cd 1d 00 00 48 89 74 24 ?? 4c 8b cb 89 74 24 ?? 45 33 c0 33 d2 48 89 74 24 ?? 48 8b cf ff 15 c6 1d 00 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}