rule Trojan_Linux_MsfShellBin_I{
	meta:
		description = "Trojan:Linux/MsfShellBin.I,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 2f 62 69 6e 2f 73 68 00 99 50 54 5f } 		$a_01_1 = {5e 6a 3b 58 0f 05 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}