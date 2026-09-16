rule Worm_Win32_Autorun_AGT{
	meta:
		description = "Worm:Win32/Autorun.AGT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 73 65 63 72 65 74 2e 65 78 65 [0-10] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } 		$a_00_1 = {59 6f 75 20 73 79 73 74 65 6d 20 69 6e 66 65 63 74 65 64 20 62 79 20 53 6c 61 73 68 20 57 6f 72 6d 21 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}