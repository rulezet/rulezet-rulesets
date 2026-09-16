rule Worm_Win32_Autorun_EV{
	meta:
		description = "Worm:Win32/Autorun.EV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 20 66 6c 61 73 68 69 6e 66 2e 64 6c 6c 20 4d 73 67 00 00 00 ff ff ff ff 04 00 00 00 6f 70 65 6e 00 00 00 00 ff ff ff ff 07 00 00 00 41 75 74 6f 52 75 6e 00 ff ff ff ff 0c 00 00 00 73 68 65 6c 6c 65 78 65 63 75 74 65 00 00 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 46 69 6e 64 5c 63 6f 6d 6d 61 } 		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } 		$a_00_2 = {64 6f 6c 70 68 69 6e 36 31 2e 64 6c 6c 20 4d 73 67 53 74 61 72 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}