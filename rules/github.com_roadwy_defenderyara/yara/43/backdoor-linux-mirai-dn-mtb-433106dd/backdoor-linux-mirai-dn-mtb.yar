rule Backdoor_Linux_Mirai_DN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08 } 		$a_00_1 = {83 c4 10 85 ff 74 19 31 c0 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a4 01 00 00 } 		$a_00_2 = {2f 64 65 76 2f 6e 75 6c 6c } 		$a_00_3 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}