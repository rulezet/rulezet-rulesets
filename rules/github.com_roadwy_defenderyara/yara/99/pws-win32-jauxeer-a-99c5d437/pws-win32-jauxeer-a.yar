rule PWS_Win32_Jauxeer_A{
	meta:
		description = "PWS:Win32/Jauxeer.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b7 8d a2 fb ff ff 0f b7 95 aa fb ff ff 8b c1 8d 8d b0 fd ff ff 03 c0 8d 04 80 03 d0 42 52 8d 95 b0 fe ff ff 52 68 ?? ?? 44 00 51 e8 ?? ?? 00 00 } 		$a_00_1 = {5c 52 65 63 79 63 6c 65 64 } 		$a_00_2 = {25 73 5c 25 64 25 64 2e 64 61 74 } 		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 73 } 	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}