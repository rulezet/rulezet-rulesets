rule Trojan_BAT_Formbook_VN_MTB_4{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0b 2b ?? 00 02 07 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 06 07 1f ?? 5d 91 61 d2 81 ?? ?? ?? 01 00 07 17 58 0b 07 02 8e 69 fe ?? 0d 09 2d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}