rule Trojan_WinNT_Adwind_P_7{
	meta:
		description = "Trojan:WinNT/Adwind.P,SIGNATURE_TYPE_JAVAHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 73 73 67 01 00 ?? 6d 61 69 6e 2f 90 04 01 06 41 2d 5a 61 2d 7a 90 1b 01 90 1b 01 90 1b 01 90 1b 01 90 1b 01 90 1b 01 [0-10] 4e 61 6d 65 43 6c 61 73 73 63 [0-10] 6d 61 69 6e 2f 90 1b 01 90 1b 01 90 1b 01 90 1b 01 90 1b 01 90 1b 01 } 		$a_01_1 = {04 64 04 06 78 06 59 78 05 82 06 08 82 07 78 05 59 78 04 82 82 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}