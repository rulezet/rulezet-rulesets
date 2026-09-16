rule Backdoor_Win32_Hupigon_FI_2{
	meta:
		description = "Backdoor:Win32/Hupigon.FI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {d6 f7 bb fa d7 d4 b6 af c9 cf cf df } 		$a_00_1 = {5c 44 65 76 69 63 65 5c 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } 		$a_02_2 = {83 f8 3a 0f 87 ?? ?? 00 00 ff 24 85 ?? ?? ?? 00 } 		$a_02_3 = {85 c0 0f 84 ?? ?? 00 00 c7 85 ?? ?? ff ff 07 00 01 00 } 		$a_00_4 = {00 42 45 49 5f 5a 48 55 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*2+(#a_00_4  & 1)*1) >=4
 
}