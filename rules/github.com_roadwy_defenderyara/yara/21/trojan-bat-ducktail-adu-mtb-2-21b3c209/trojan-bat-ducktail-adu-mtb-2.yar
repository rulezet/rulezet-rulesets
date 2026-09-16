rule Trojan_BAT_DuckTail_ADU_MTB_2{
	meta:
		description = "Trojan:BAT/DuckTail.ADU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 42 07 08 28 ?? ?? ?? 2b 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 04 07 08 1f 10 58 28 ?? ?? ?? 2b 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 05 11 04 11 05 73 1d 00 00 06 09 6f ?? ?? ?? 06 0d 08 1f 20 59 0c 08 16 2f ba } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}