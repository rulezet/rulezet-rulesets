rule Trojan_Win32_Formbook_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 19 04 ?? 34 ?? 04 ?? 88 04 19 41 3b cf 72 ef } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}