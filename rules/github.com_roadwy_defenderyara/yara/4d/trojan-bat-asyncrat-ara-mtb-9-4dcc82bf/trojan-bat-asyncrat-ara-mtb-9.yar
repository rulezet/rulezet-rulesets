rule Trojan_BAT_AsyncRAT_ARA_MTB_9{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 37 32 2e 38 36 2e 39 36 2e 31 31 31 3a 38 30 38 30 2f 53 63 72 69 70 74 2e 70 73 31 } 		$a_01_1 = {55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 20 24 6c 6f 63 61 6c 50 61 74 68 } 		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 20 24 6c 6f 63 61 6c 50 61 74 68 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}