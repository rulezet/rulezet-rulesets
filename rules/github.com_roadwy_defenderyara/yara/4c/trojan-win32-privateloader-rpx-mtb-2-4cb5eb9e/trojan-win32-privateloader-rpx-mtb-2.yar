rule Trojan_Win32_PrivateLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/PrivateLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 84 24 ?? ?? 00 00 50 ff d6 8d 8c 24 ?? 00 00 00 51 ff d7 6a 00 6a 00 ff d3 8d 94 24 ?? ?? 00 00 52 6a 00 ff d5 83 6c 24 10 01 75 ac } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}