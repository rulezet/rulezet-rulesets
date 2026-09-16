rule Trojan_BAT_Masslogger_VN_MTB_2{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0c 19 8d ?? ?? ?? 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 73 ?? ?? ?? 06 0d 2a 90 09 10 00 7e ?? ?? ?? 04 0a 7e ?? ?? ?? 04 0b 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}