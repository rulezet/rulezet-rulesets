rule TrojanSpy_Win32_Swisyn_A_2{
	meta:
		description = "TrojanSpy:Win32/Swisyn.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_00_0 = {6e 74 6c 6f 67 2e 73 79 73 } 		$a_00_1 = {6e 74 63 6f 6d 2e 64 6c 6c } 		$a_00_2 = {68 61 7a 69 72 6c 61 } 		$a_00_3 = {75 73 65 72 3d } 		$a_00_4 = {64 65 73 74 69 6e 6f 3d } 		$a_00_5 = {63 6f 6e 74 65 75 64 6f 3d } 		$a_00_6 = {45 72 72 6f 72 20 6f 6e 20 46 46 46 46 46 46 46 46 46 } 		$a_00_7 = {00 2f 31 73 74 65 6d 00 } 		$a_00_8 = {00 6c 2e 70 68 70 00 } 		$a_03_9 = {ff b5 c8 fe ff ff 68 ?? ?? ?? ?? ff b5 ec fe ff ff ff b5 ec fe ff ff ff b5 ec fe ff ff 68 ?? ?? ?? ?? ff b5 d0 fe ff ff ff b5 d4 fe ff ff ff b5 d0 fe ff ff ff b5 d0 fe ff ff ff b5 d8 fe ff ff 68 ?? ?? ?? ?? ff b5 cc fe ff ff ff b5 dc fe ff ff ff b5 e4 fe ff ff ff b5 e0 fe ff ff 68 ?? ?? ?? ?? ff b5 f4 fe ff ff ff b5 cc fe ff ff 68 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_03_9  & 1)*3) >=7
 
}