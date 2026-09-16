rule Trojan_BAT_Dnoper_ADN_MTB_2{
	meta:
		description = "Trojan:BAT/Dnoper.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 16 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 28 ?? 00 00 0a 00 7e ?? 00 00 0a 72 ?? 00 00 70 17 6f ?? 00 00 0a 0b 00 07 72 ?? 00 00 70 06 6f ?? 00 00 0a 00 00 de 10 07 14 fe 01 0c 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}