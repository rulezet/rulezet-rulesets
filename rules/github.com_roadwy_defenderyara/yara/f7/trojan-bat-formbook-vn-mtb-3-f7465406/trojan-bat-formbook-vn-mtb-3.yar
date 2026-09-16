rule Trojan_BAT_Formbook_VN_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 d2 81 ?? ?? ?? 01 00 06 17 58 0a 06 02 8e 69 fe ?? 0c 08 2d 90 09 15 00 02 06 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 7e ?? ?? ?? 04 06 1f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}