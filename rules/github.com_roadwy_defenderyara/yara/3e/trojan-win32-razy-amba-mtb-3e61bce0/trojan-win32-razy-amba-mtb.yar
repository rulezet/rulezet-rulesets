rule Trojan_Win32_Razy_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Razy.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 f0 29 f0 31 1f 09 f0 47 39 cf } 		$a_01_1 = {8b 1b 29 c0 81 e3 ff 00 00 00 42 81 fa f4 01 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}