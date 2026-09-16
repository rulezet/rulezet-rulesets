rule Trojan_Win32_Injector_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 8c 2a 00 00 00 83 ff 03 48 } 		$a_01_1 = {83 fe 3f c7 84 24 7c ff ff ff f6 00 00 00 83 f9 40 89 3e } 		$a_01_2 = {c7 44 24 8c b3 00 00 00 81 fa aa 00 00 00 81 ff cd 00 00 00 81 f9 d2 00 00 00 } 		$a_01_3 = {89 3e c7 84 24 7c ff ff ff 00 00 00 00 83 fa 0a 83 f9 3f } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2) >=6
 
}