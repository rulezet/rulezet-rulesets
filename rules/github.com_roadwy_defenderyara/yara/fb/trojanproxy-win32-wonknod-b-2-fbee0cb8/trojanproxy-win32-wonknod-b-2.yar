rule TrojanProxy_Win32_Wonknod_B_2{
	meta:
		description = "TrojanProxy:Win32/Wonknod.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6e 61 6d 65 66 ?? 45 e4 3d 00 c7 45 ?? 63 6f 6e 74 } 		$a_01_1 = {67 65 74 66 69 6c 65 2e 6c 70 3f 6e 61 6d 65 3d 64 62 2e 7a 69 70 26 61 63 74 69 6f 6e 3d 61 72 67 } 		$a_01_2 = {31 6f 6e 5f 6d 6f 6e 69 74 6f 72 54 69 6d 65 72 5f 74 69 6d 65 6f 75 74 28 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}