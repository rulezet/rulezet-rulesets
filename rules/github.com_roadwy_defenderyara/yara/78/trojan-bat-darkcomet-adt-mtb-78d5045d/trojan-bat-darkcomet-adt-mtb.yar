rule Trojan_BAT_DarkComet_ADT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0b 61 d2 9c 07 1f 0b 58 0b 07 08 31 ed } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}