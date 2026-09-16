rule Trojan_Win64_Lazy_AH_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 20 3e 6e 75 6c 20 26 26 20 64 65 6c 20 2f 66 20 2f 71 20 } 		$a_81_1 = {69 6e 6a 65 63 74 5f 68 65 6c 70 65 72 5f 78 36 34 2e 65 78 65 } 		$a_81_2 = {65 78 74 72 61 63 74 5f 6b 65 79 73 5f 78 36 34 2e 64 6c 6c } 		$a_81_3 = {5b 56 32 30 5f 4e 4f 5f 4b 45 59 5d } 	condition:
		((#a_81_0  & 1)*40+(#a_81_1  & 1)*30+(#a_81_2  & 1)*20+(#a_81_3  & 1)*10) >=100
 
}