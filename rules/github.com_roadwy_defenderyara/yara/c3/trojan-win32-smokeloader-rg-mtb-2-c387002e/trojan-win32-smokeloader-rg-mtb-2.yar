rule Trojan_Win32_SmokeLoader_RG_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}