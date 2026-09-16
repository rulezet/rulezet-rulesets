rule Trojan_BAT_Formbook_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 04 61 05 59 20 ?? ?? 00 00 58 } 		$a_03_1 = {02 03 61 04 59 20 ?? ?? 00 00 58 } 		$a_01_2 = {11 0e 08 11 08 1f 16 5d 91 61 13 0f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}