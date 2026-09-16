rule Trojan_Win32_Emotet_R_MTB{
	meta:
		description = "Trojan:Win32/Emotet.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 55 4f 45 57 49 5a 55 46 45 } 		$a_00_1 = {53 00 49 00 43 00 55 00 48 00 48 00 54 00 4a 00 49 00 4e 00 } 		$a_00_2 = {43 00 67 00 79 00 4f 00 77 00 73 00 75 00 68 00 62 00 53 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=5
 
}