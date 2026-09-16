rule Trojan_Win32_RemcosRAT_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/RemcosRAT.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 73 00 73 00 75 00 72 00 65 00 72 00 20 00 67 00 65 00 6e 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 65 00 73 } 		$a_01_1 = {73 00 69 00 66 00 74 00 65 00 72 00 20 00 73 00 6b 00 61 00 6b 00 6b 00 65 00 72 00 6e 00 65 00 73 } 	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}