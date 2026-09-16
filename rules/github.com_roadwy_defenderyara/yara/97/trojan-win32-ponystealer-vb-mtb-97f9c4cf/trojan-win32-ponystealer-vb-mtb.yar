rule Trojan_Win32_PonyStealer_VB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {77 00 37 00 58 00 76 00 54 00 33 00 65 00 42 00 32 00 75 00 74 00 70 00 61 00 46 00 33 00 32 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}