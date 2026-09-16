rule Trojan_BAT_Rozena_ARZ_MTB_4{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 06 16 08 07 28 ?? ?? ?? 0a 7e 02 00 00 0a 16 08 7e 02 00 00 0a 16 7e 02 00 00 0a 28 ?? ?? ?? 06 0d 09 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}