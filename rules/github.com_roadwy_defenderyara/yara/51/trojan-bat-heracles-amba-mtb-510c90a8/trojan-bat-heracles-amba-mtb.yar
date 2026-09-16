rule Trojan_BAT_Heracles_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 16 9a 26 16 2d f9 00 28 ?? 00 00 06 72 ?? ?? 00 70 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}