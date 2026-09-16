rule Trojan_Win32_PonyStealer_VB_MTB_5{
	meta:
		description = "Trojan:Win32/PonyStealer.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {4a 00 53 00 54 00 6f 00 75 00 56 00 61 00 48 00 74 00 73 00 68 00 74 00 34 00 64 00 43 00 55 00 48 00 4a 00 36 00 77 00 55 00 39 00 57 00 5a 00 4b 00 39 00 41 00 69 00 69 00 6a 00 55 00 39 00 77 00 7a 00 46 00 42 00 6b 00 5a 00 62 00 57 00 54 00 4f 00 6d 00 4f 00 6a 00 37 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}