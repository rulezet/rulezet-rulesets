rule Trojan_Win32_Relnicar_A_dha_5{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 73 63 2e 64 6c 6c 00 5f 72 75 6e 40 34 00 } 		$a_03_1 = {b9 69 00 00 00 66 89 0c 45 [0-04] 68 00 00 00 80 b9 6f 00 00 00 68 [0-04] 66 89 0c 45 } 	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}