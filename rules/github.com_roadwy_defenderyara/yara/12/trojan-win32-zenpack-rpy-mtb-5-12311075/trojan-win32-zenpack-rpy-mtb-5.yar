rule Trojan_Win32_Zenpack_RPY_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 e8 fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 ec fe ff ff } 		$a_01_1 = {ff d0 83 ec 04 3d 00 00 00 00 0f 94 c1 88 8d e7 fe ff ff 8a 85 e7 fe ff ff a8 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}