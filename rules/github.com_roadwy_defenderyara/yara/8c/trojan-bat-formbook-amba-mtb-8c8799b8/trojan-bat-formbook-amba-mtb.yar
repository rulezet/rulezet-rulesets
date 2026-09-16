rule Trojan_BAT_Formbook_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0f 11 07 5d d2 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}