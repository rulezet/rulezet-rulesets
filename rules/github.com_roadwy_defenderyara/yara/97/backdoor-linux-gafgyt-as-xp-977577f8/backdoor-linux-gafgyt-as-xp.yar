rule Backdoor_Linux_Gafgyt_AS_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 4c 4d 41 4f } 		$a_01_1 = {2f 64 65 76 2f 6e 65 74 73 6c 69 6e 6b 2f } 		$a_01_2 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}