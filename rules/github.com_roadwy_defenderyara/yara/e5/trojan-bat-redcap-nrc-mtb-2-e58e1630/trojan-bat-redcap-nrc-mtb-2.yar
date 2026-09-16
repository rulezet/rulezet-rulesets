rule Trojan_BAT_Redcap_NRC_MTB_2{
	meta:
		description = "Trojan:BAT/Redcap.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1a 00 00 01 13 04 7e ?? 00 00 04 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 04 16 11 05 6f ?? 00 00 0a 13 06 09 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 09 6f ?? 00 00 0a 2c bb } 		$a_01_1 = {63 70 70 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}