rule PWS_Win32_Fareit_K_MTB{
	meta:
		description = "PWS:Win32/Fareit.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_02_0 = {b9 77 00 00 00 6a 00 e2 fc 68 ?? ?? ?? ?? 6a 00 68 e8 01 00 00 89 65 10 81 c4 e8 01 00 00 e9 ?? ?? 00 00 } 		$a_02_1 = {0f 31 49 29 c2 50 5a 83 f9 02 75 f4 01 cb 02 5d 64 ff d3 e8 ?? ?? ff ff } 		$a_00_2 = {73 68 65 6c 6c 33 32 } 		$a_00_3 = {73 68 65 6c 6c 33 32 2e 64 6c 6c } 		$a_00_4 = {6b 65 72 6e 65 6c 33 32 } 		$a_00_5 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-1) >=4
 
}