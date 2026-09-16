rule Trojan_BAT_njRAT_A_MTB_3{
	meta:
		description = "Trojan:BAT/njRAT.A!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 8f 5b 00 00 01 25 71 5b 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 5b 00 00 01 16 13 0e 11 06 17 58 13 06 1c } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}