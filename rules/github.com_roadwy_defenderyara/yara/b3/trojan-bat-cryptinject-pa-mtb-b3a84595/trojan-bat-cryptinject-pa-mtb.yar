rule Trojan_BAT_CryptInject_PA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 15 d2 13 30 11 15 1e 63 d1 13 15 11 1a 11 0b 91 13 26 11 1a 11 0b ?? ?? ?? ?? ?? ?? ?? ?? 58 61 11 30 61 d2 9c 11 26 13 1e ?? ?? ?? 58 13 0b 11 0b 11 27 32 a4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}