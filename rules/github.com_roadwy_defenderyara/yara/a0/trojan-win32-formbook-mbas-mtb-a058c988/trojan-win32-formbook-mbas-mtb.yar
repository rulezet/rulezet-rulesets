rule Trojan_Win32_Formbook_MBAS_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 de } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}