rule Trojan_BAT_Masslogger_VN_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 73 ?? ?? ?? 06 0a 02 28 ?? ?? ?? 06 00 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}