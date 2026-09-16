rule Trojan_Win32_PonyStealer_VB_MTB_4{
	meta:
		description = "Trojan:Win32/PonyStealer.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {68 00 56 00 67 00 35 00 32 00 39 00 6b 00 59 00 74 00 51 00 76 00 54 00 44 00 56 00 52 00 63 00 49 00 50 00 57 00 56 00 5a 00 50 00 47 00 48 00 55 00 44 00 50 00 31 00 38 00 32 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}