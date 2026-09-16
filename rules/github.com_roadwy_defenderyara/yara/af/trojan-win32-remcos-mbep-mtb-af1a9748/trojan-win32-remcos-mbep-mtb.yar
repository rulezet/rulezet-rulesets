rule Trojan_Win32_Remcos_MBEP_MTB{
	meta:
		description = "Trojan:Win32/Remcos.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d4 25 40 00 1a f9 70 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 e4 24 40 00 20 24 40 00 30 12 40 00 78 00 00 00 8c } 		$a_01_1 = {42 61 72 6d 68 6a 65 72 74 69 67 68 65 64 65 72 6e 65 33 00 53 6f 6e 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}