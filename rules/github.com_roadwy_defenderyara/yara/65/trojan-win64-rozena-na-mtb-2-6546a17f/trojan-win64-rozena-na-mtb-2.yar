rule Trojan_Win64_Rozena_NA_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 11 74 24 40 0f 11 7c 24 ?? 44 0f 11 44 24 ?? 83 39 06 0f 87 cd 00 00 00 8b 01 48 8d 15 ?? ?? ?? ?? 48 63 04 82 48 01 d0 } 		$a_03_1 = {48 8b 4c 24 20 48 8b 54 24 ?? 41 b8 40 00 00 00 48 03 3d ?? ?? ?? ?? 48 89 4f 08 49 89 f9 48 89 57 ?? ff 15 9c 5e 0c 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}