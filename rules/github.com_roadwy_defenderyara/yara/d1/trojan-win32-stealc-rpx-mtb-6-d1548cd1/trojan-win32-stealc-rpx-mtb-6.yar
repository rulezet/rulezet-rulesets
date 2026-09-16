rule Trojan_Win32_Stealc_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff d3 ff d6 4f 75 e3 5f 5e 33 c0 5b c2 10 00 } 		$a_01_1 = {8b 54 24 10 8b 4c 24 14 41 89 4c 24 14 3b 8c 24 20 08 00 00 7c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}