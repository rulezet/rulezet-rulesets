rule Trojan_BAT_StealerC_AMAG_MTB{
	meta:
		description = "Trojan:BAT/StealerC.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 ?? 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}