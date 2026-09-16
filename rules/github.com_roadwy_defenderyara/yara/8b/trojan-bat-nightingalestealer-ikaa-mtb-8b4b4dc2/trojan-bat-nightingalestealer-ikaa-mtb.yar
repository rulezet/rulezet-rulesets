rule Trojan_BAT_NightingaleStealer_IKAA_MTB{
	meta:
		description = "Trojan:BAT/NightingaleStealer.IKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b } 		$a_81_1 = {7b 37 7d 5b 35 5d 5b 32 30 5d 7b 32 30 7d 5b 32 35 5d 5b 31 36 5d 5b 35 5d } 		$a_81_2 = {7b 31 7d 5b 31 39 5d 5b 31 39 5d 5b 35 5d 5b 31 33 5d 5b 32 5d 5b 31 32 5d 5b 32 35 5d } 		$a_81_3 = {7b 31 32 7d 5b 31 35 5d 5b 31 5d 5b 34 5d } 		$a_81_4 = {7b 35 7d 5b 31 34 5d 5b 32 30 5d 5b 31 38 5d 5b 32 35 5d 7b 31 36 7d 5b 31 35 5d 5b 39 5d 5b 31 34 5d 5b 32 30 5d } 		$a_81_5 = {7b 39 7d 5b 31 34 5d 5b 32 32 5d 5b 31 35 5d 5b 31 31 5d 5b 35 5d } 	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}