rule Rogue_Win32_Onescan_32{
	meta:
		description = "Rogue:Win32/Onescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 61 6c 63 6c 65 61 6e 65 72 2d 64 65 6c } 		$a_01_1 = {72 65 61 6c 63 6c 65 61 6e 65 72 2e 63 6f 2e 6b 72 } 		$a_01_2 = {26 73 74 72 50 43 3d 25 73 26 73 74 72 49 44 3d 25 73 26 73 74 72 53 69 74 65 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}