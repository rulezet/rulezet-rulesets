rule Trojan_BAT_Remcos_ARS_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 20 00 11 0a 11 0f 8f ?? 00 00 01 25 47 11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 11 0f 17 58 13 0f 11 0f 11 0a 8e 69 } 		$a_03_1 = {2b 21 00 11 09 11 08 11 0d 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 0d 18 58 13 0d 11 0d 11 08 6f ?? 00 00 0a fe 04 13 0e 11 0e 2d ce } 		$a_01_2 = {57 00 61 00 67 00 67 00 65 00 72 00 41 00 70 00 70 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}