rule Trojan_Win32_Zenpack_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 e4 fe ff ff ff d1 83 ec 04 8b 8d e4 fe ff ff 81 c1 01 00 00 00 89 e2 89 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}