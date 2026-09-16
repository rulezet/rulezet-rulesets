rule Trojan_Win32_Zenpack_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 ec fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff } 		$a_01_1 = {8d 85 fc fe ff ff 05 04 00 00 00 89 85 e8 fe ff ff 8b 85 e8 fe ff ff 80 38 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}