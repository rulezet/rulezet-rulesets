rule Rogue_Win32_Winwebsec_15{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {dc b9 9e f7 bd d7 cd f7 bd d7 cd f7 bd d7 cd e9 ef 42 cd e9 bd d7 cd e9 ef 54 cd 74 bd d7 cd e9 ef 53 cd c4 bd d7 cd d0 7b ba cd ff bd d7 cd d0 7b ac cd ec bd d7 cd f7 bd d6 cd 9b bc d7 cd 0b 9d c5 cd f9 bd d7 cd e9 ef 5d cd cc bd d7 cd e9 ef 43 cd f6 bd d7 cd e9 ef 46 cd f6 bd d7 cd 52 69 63 68 f7 bd d7 cd 01 } 		$a_4c_1 = {03 00 57 2e 79 4d 00 00 00 00 00 00 00 00 e0 00 03 } 	condition:
		((#a_11_0  & 1)*1+(#a_4c_1  & 1)*21504) >=2
 
}