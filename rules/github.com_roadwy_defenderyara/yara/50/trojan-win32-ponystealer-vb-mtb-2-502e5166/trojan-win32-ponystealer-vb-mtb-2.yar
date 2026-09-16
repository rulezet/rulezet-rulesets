rule Trojan_Win32_PonyStealer_VB_MTB_2{
	meta:
		description = "Trojan:Win32/PonyStealer.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {4e 00 49 00 57 00 56 00 57 00 66 00 46 00 31 00 34 00 50 00 6a 00 68 00 32 00 57 00 61 00 6c 00 64 00 75 00 6d 00 6e 00 73 00 34 00 30 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}