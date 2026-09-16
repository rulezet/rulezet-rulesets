rule Trojan_Win64_Rozena_NR_MTB_7{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 33 66 0f 6f 05 ?? ?? ?? ?? 48 83 c8 ff f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 0e cf 94 00 f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 17 cf 94 } 		$a_01_1 = {73 74 65 61 6d 5f 6d 6f 64 75 6c 65 5f 78 36 34 2e 70 64 62 } 		$a_01_2 = {70 72 69 6d 6f 72 64 69 61 6c 5f 63 72 61 63 6b } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}