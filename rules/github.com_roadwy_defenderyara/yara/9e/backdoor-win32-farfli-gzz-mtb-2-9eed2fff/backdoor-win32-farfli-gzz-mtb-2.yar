rule Backdoor_Win32_Farfli_GZZ_MTB_2{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 80 b4 05 ?? ?? ?? ?? d7 40 3d c0 67 0f 00 75 } 		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 75 70 64 61 74 65 2e 65 78 65 } 		$a_01_2 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 66 64 73 2e 74 78 74 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}