rule Trojan_BAT_Quasar_AQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1b 00 06 02 07 1e 6f 22 00 00 0a 18 28 23 00 00 0a 6f 24 00 00 0a 00 00 07 1e 58 0b 07 02 6f 25 00 00 0a fe 04 0c 08 2d d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}