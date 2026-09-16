rule Trojan_Win32_Zenloader_C{
	meta:
		description = "Trojan:Win32/Zenloader.C,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } 		$a_00_1 = {2c 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 6d 00 61 00 69 00 6e 00 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}