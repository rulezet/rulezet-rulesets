rule Trojan_BAT_Formbook_PD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 04 05 5d 05 58 05 5d 91 0a 2b 00 06 2a } 		$a_03_1 = {00 04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e ?? 61 0e ?? 59 20 00 02 00 00 58 0c 08 0d 2b 00 09 2a } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}