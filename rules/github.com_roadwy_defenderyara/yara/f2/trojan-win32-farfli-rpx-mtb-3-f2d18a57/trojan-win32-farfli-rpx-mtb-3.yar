rule Trojan_Win32_Farfli_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 57 5b 01 fb e8 ?? 00 00 00 81 ef 01 00 00 00 21 df 31 11 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}