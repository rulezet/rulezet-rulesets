rule Worm_Win32_Moldyow_A{
	meta:
		description = "Worm:Win32/Moldyow.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {53 50 49 36 34 2e 64 6c 6c ?? 55 6e 48 6f } 		$a_02_1 = {5c 69 6d 65 5c [0-03] 2e 64 6c 6c } 		$a_00_2 = {77 73 32 5f 34 32 2e 64 6c 6c } 		$a_00_3 = {8a 94 07 94 01 00 00 69 c9 06 03 00 00 03 c8 40 } 		$a_00_4 = {de de 99 f7 7d 10 8b 45 0c 0f be 04 02 33 41 04 99 f7 fb } 	condition:
		((#a_02_0  & 1)*4+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*4) >=5
 
}