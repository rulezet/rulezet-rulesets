rule PWS_Win32_OnLineGames_NZ_bit_2{
	meta:
		description = "PWS:Win32/OnLineGames.NZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 6e 73 5f 68 65 6c 70 65 72 2e 64 6c 6c } 		$a_01_1 = {63 66 5f 72 65 70 61 69 72 2e 64 6c 6c } 		$a_01_2 = {64 6e 66 5f 68 65 6c 70 65 72 2e 64 6c 6c } 		$a_01_3 = {6c 6f 6c 5f 74 6f 6f 6c 73 2e 64 6c 6c } 		$a_01_4 = {67 61 6d 65 5f 6d 67 72 2e 64 6c 6c 2e 64 6c 6c } 		$a_01_5 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c 00 48 61 6e 64 6c 65 48 6f 6f 6b 52 65 63 76 44 61 74 61 5f 46 72 6f 6d 4c 73 70 } 		$a_01_6 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*4+(#a_01_6  & 1)*1) >=5
 
}