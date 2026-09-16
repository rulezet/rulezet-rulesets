rule Trojan_BAT_Formbook_VN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 ?? ?? ?? 70 a2 25 17 7e ?? ?? ?? 04 a2 25 18 7e ?? ?? ?? 04 a2 0a 06 28 ?? ?? ?? 0a 00 06 73 ?? ?? ?? 06 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}