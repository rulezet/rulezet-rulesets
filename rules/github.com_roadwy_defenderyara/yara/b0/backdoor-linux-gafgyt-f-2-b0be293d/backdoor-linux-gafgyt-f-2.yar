rule Backdoor_Linux_Gafgyt_F_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.F,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 75 61 77 65 69 5f 6b 69 6c 6c } 		$a_80_1 = {3c 4e 65 77 53 74 61 74 75 73 55 52 4c 3e 24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 } 		$a_80_2 = {3c 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e 24 28 65 63 68 6f 20 48 55 41 57 45 49 55 50 4e 50 29 3c 2f 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e } 		$a_03_3 = {31 c0 ff c0 80 75 00 ?? 48 ff c5 41 39 c4 75 f2 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}