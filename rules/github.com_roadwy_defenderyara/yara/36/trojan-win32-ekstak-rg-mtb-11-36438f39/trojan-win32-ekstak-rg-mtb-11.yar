rule Trojan_Win32_Ekstak_RG_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 15 58 82 46 00 6a 00 ff 15 40 86 46 00 85 c0 7d 12 3d 06 01 01 80 75 11 68 00 b1 46 00 ff d3 85 c0 74 06 ff 15 44 86 46 00 e9 } 		$a_01_1 = {41 00 63 00 72 00 6f 00 42 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}