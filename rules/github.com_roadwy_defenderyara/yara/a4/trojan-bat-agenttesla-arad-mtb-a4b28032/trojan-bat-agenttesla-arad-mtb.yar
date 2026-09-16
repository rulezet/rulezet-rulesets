rule Trojan_BAT_Agenttesla_ARAD_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 03 07 91 04 07 04 8e 69 5d 91 61 b4 9c 07 17 d6 0b 07 03 8e 69 32 e7 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}