rule Trojan_Win32_SusDeathStalker_A{
	meta:
		description = "Trojan:Win32/SusDeathStalker.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 } 		$a_80_1 = {6c 69 73 74 20 } 		$a_80_2 = {73 68 61 64 6f 77 73 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}