rule Backdoor_Linux_Gafgyt_F{
	meta:
		description = "Backdoor:Linux/Gafgyt.F,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 6f 61 74 6e 65 74 } 		$a_00_1 = {73 65 6c 66 20 72 65 70 20 6e 65 74 69 73 20 61 6e 64 20 6e 72 70 65 20 67 6f 74 } 		$a_00_2 = {38 30 2e 32 31 31 2e 37 35 2e 33 35 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=4
 
}