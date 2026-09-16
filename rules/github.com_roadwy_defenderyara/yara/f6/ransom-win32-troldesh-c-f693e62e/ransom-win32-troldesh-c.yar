rule Ransom_Win32_Troldesh_C{
	meta:
		description = "Ransom:Win32/Troldesh.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 49 6e 74 32 53 74 72 28 22 } 		$a_01_1 = {58 00 51 00 38 00 7a 00 68 00 00 00 } 		$a_01_2 = {2a 00 5c 00 41 00 44 00 3a 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}