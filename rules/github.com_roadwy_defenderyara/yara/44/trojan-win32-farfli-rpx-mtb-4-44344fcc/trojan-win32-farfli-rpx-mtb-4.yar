rule Trojan_Win32_Farfli_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d ff 81 e1 ff 00 00 00 8b 55 fe 81 e2 ff 00 00 00 0b ca 85 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}