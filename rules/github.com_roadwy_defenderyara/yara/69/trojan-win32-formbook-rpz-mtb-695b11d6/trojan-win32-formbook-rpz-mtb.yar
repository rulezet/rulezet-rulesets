rule Trojan_Win32_Formbook_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ab aa aa 2a f7 eb c1 fa 02 8b da c1 eb 1f 03 da 75 ed } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}