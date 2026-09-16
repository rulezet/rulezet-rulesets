rule Worm_Win32_Taterf_gen_E_2{
	meta:
		description = "Worm:Win32/Taterf.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d7 25 ff ff 00 00 3d 16 1c 00 00 76 08 3d 20 1c 00 00 73 01 cc } 		$a_03_1 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 (?? 3d 20 1c 00 00 73 ?? cc 0f 3d 20 1c|00 00 73 08 6a 00 ff 15 )} 		$a_03_2 = {58 83 38 00 75 1f ff 00 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff 74 24 10 90 09 09 00 e8 04 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}