rule Trojan_Linux_Mirai_AMTB_2{
	meta:
		description = "Trojan:Linux/Mirai!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 72 6f 75 74 65 72 2e 6c 62 6c 69 6e 6b 2d 72 65 70 2e 73 68 } 		$a_80_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 64 76 72 2e 6c 69 6c 69 6e 2d 72 65 70 2e 73 68 } 		$a_80_2 = {62 6f 79 6d 6f 64 65 72 2e 64 64 6e 73 2e 6e 65 74 } 		$a_80_3 = {24 28 77 67 65 74 24 7b 49 46 53 7d 68 74 74 70 3a 2f 2f 25 73 2f 64 76 72 2e 74 76 74 2d 72 65 70 2e 73 68 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=10
 
}