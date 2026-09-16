rule Trojan_BAT_Quasar_AQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e b7 0b 16 02 8e b7 17 da 0d 0c 2b 10 02 08 02 08 91 03 08 07 5d 91 61 9c 08 17 d6 0c 08 09 31 ec 02 0a 2b 00 06 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}