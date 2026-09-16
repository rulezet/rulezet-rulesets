rule Trojan_Win64_Tedy_AHE_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 ba e5 59 29 8d 0f c6 6d 97 48 89 94 24 0e 02 00 00 48 ba 59 f0 95 59 ae 33 50 0c 48 89 94 24 16 02 00 00 48 ba b1 4d 2c 80 1d dd 70 c5 48 89 94 24 1e 02 00 00 } 		$a_01_1 = {48 8b 54 24 58 48 89 50 18 48 8b 54 24 20 48 89 50 20 48 8b 49 10 48 89 c3 } 		$a_00_2 = {6d 61 69 6e 2e 64 65 6f 62 66 75 73 63 61 74 65 53 68 65 6c 6c 63 6f 64 65 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*40+(#a_00_2  & 1)*10) >=70
 
}