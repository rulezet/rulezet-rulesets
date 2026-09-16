rule Trojan_Win32_PrivateLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f5 66 3b ee 89 75 bc 8b f7 f6 c1 a9 d3 e6 8b 4d 0c 66 3b fb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}