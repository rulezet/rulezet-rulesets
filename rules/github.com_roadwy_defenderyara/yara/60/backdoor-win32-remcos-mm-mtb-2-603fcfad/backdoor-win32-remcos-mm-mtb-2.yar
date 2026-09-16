rule Backdoor_Win32_Remcos_MM_MTB_2{
	meta:
		description = "Backdoor:Win32/Remcos.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } 		$a_01_1 = {25 f0 07 00 00 66 0f 28 a0 80 09 46 00 66 0f 28 b8 70 05 46 00 66 0f 54 f0 66 0f 5c c6 66 0f 59 f4 66 0f 5c f2 f2 0f 58 fe 66 0f 59 c4 66 0f 28 e0 } 		$a_01_2 = {52 65 6d 63 6f 73 20 72 65 73 74 61 72 74 65 64 20 62 79 20 77 61 74 63 68 64 6f 67 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=13
 
}