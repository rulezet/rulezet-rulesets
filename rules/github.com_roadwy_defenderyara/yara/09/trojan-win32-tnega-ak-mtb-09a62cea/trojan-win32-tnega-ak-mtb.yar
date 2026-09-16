rule Trojan_Win32_Tnega_AK_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 14 53 56 57 89 65 e8 e9 } 		$a_01_1 = {62 00 6d 00 70 00 72 00 65 00 73 00 2e 00 64 00 6c 00 6c 00 } 		$a_01_2 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } 		$a_01_3 = {4c 64 72 55 6e 6c 6f 63 6b 4c 6f 61 64 65 72 4c 6f 63 6b } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}