rule Trojan_Win32_PonyStealer_VB_MTB_3{
	meta:
		description = "Trojan:Win32/PonyStealer.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {47 00 66 00 39 00 4c 00 6d 00 30 00 46 00 34 00 37 00 53 00 53 00 69 00 62 00 4c 00 6c 00 4e 00 69 00 54 00 47 00 4d 00 41 00 78 00 71 00 49 00 75 00 57 00 62 00 31 00 37 00 34 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}