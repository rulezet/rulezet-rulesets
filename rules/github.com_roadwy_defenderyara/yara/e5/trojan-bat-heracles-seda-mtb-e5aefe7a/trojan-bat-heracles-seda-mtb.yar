rule Trojan_BAT_Heracles_SEDA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 01 00 0a 11 } 		$a_03_1 = {58 12 02 28 ?? 00 00 0a 58 20 88 13 00 00 5d 20 e8 03 00 00 58 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}