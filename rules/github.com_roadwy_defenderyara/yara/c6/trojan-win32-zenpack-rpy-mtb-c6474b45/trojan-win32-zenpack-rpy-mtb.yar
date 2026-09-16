rule Trojan_Win32_Zenpack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d c8 fe ff ff 80 39 53 0f 94 c3 8b 95 c4 fe ff ff 80 3a 54 0f 94 c7 20 fb 8b b5 c0 fe ff ff 80 3e 45 0f 94 c7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}