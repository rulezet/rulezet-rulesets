rule Trojan_BAT_Heracles_BAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 92 00 00 0a 03 07 6f 92 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 1c 00 00 0a 32 e1 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}