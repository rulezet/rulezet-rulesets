rule Backdoor_Linux_Mirai_Ch_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5 } 		$a_01_1 = {53 45 52 56 5a 55 58 4f } 		$a_01_2 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}