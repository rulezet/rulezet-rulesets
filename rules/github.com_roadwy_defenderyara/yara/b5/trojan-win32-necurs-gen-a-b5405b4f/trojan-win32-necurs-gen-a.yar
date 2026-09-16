rule Trojan_Win32_Necurs_gen_A{
	meta:
		description = "Trojan:Win32/Necurs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 85 fc fc ff ff 72 c6 85 fd fc ff ff 77 c6 85 fe fc ff ff 63 c6 85 ff fc ff ff 00 } 		$a_01_1 = {ff d2 33 c0 b0 04 03 e0 } 		$a_01_2 = {3d 35 8e f8 1f 6a 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}