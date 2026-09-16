rule Trojan_Win64_Rozena_NR_MTB_4{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d c3 99 12 00 48 8b 01 48 05 ?? ?? ?? ?? 48 89 41 10 48 89 41 18 } 		$a_03_1 = {48 8d 3d 63 9f 12 00 e8 c6 3f 00 00 65 48 8b 1c 25 ?? ?? ?? ?? 48 c7 83 00 00 00 00 23 01 00 00 48 8b 05 ?? ?? ?? ?? 48 3d 23 01 00 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}