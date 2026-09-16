rule Trojan_Win64_Lazy_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 50 48 8b 8c 24 a0 05 00 00 33 d2 0f b6 3c 11 40 88 3c 10 48 ff c2 40 84 ff 75 } 		$a_01_1 = {72 75 6e 20 73 68 65 6c 6c 63 6f 64 65 } 		$a_01_2 = {62 65 67 69 6e 20 6c 6f 61 64 20 73 68 65 6c 6c 63 6f 64 65 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=30
 
}