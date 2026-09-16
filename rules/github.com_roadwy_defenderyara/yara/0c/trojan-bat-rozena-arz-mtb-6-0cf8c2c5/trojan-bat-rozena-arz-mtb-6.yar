rule Trojan_BAT_Rozena_ARZ_MTB_6{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 08 8e 69 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 0d 08 16 09 6e 28 ?? 00 00 0a 08 8e 69 28 ?? 00 00 0a 16 16 09 07 16 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}