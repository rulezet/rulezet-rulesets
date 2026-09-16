rule Trojan_Win32_SmokeLoader_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 ff d6 ff d7 4b 75 f7 } 		$a_01_1 = {56 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d3 6a 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}