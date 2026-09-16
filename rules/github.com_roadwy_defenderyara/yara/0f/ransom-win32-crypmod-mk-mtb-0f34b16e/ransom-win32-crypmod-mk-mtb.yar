rule Ransom_Win32_Crypmod_MK_MTB{
	meta:
		description = "Ransom:Win32/Crypmod.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 7a 69 70 } 		$a_01_1 = {25 64 20 2b 20 25 64 20 3d 20 25 64 } 		$a_01_2 = {65 63 68 6f 20 4f 70 73 2c 20 73 65 75 73 20 61 72 71 75 69 76 6f 73 20 66 6f 72 61 6d 20 63 72 69 70 74 6f 67 72 61 66 61 64 6f 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}