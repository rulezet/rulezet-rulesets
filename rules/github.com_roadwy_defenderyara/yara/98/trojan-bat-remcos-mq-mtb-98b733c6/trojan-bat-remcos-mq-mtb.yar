rule Trojan_BAT_Remcos_MQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 0b 75 42 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}