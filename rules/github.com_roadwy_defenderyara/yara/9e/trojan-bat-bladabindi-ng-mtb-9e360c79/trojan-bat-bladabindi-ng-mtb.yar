rule Trojan_BAT_Bladabindi_NG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 30 00 00 04 0e 06 17 59 95 58 0e 05 28 ?? 02 00 06 58 54 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}