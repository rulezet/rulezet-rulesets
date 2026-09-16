rule Trojan_BAT_Quasar_AQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 80 04 00 00 04 02 16 7e ?? 00 00 04 02 8e 69 28 ?? 00 00 0a 7e ?? 00 00 04 d0 05 00 00 02 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}