rule Ransom_Win32_Clop_PB_MTB{
	meta:
		description = "Ransom:Win32/Clop.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } 		$a_01_1 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 5f 00 21 00 21 00 21 00 2e 00 54 00 58 00 54 00 } 		$a_01_2 = {2e 00 43 00 5f 00 4c 00 5f 00 4f 00 5f 00 50 00 } 		$a_01_3 = {25 00 73 00 20 00 72 00 75 00 6e 00 72 00 75 00 6e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}