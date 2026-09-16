rule Trojan_BAT_Masslogger_VN_MTB_3{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 90 09 1e 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 91 fe ?? ?? 00 61 fe ?? ?? 00 fe ?? ?? 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}