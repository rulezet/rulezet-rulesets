rule Backdoor_Win32_Stradatu_2{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 71 66 69 6c 65 20 6e 6f 74 20 65 78 69 73 74 21 } 		$a_01_1 = {64 20 66 69 6c 65 20 66 61 69 6c 75 72 65 21 } 		$a_01_2 = {59 32 31 6b 4c 6d 56 34 5a 51 3d 3d } 		$a_01_3 = {52 55 68 65 59 6f 64 74 61 58 79 75 64 54 79 34 61 33 49 35 4e 6a 56 78 4e 6b 5a 78 50 52 21 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}