rule Trojan_Win64_Farfli_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 64 6c 6c c6 45 ?? 00 c7 45 ?? 69 6c 65 54 c7 45 ?? 69 6d 65 00 c7 45 ?? 69 6c 65 54 c7 45 ?? 69 6d 65 00 c7 45 ?? 54 69 6d 65 } 		$a_01_1 = {80 30 46 48 8d 40 01 ff c1 81 f9 08 02 00 00 } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}