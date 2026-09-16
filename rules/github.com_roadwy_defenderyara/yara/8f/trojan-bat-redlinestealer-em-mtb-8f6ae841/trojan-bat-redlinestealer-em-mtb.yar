rule Trojan_BAT_RedLineStealer_EM_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 1b 59 8d 42 00 00 01 0b 02 1b 07 16 02 8e 69 1b 59 28 9f 00 00 0a 00 07 16 14 28 40 00 00 2b 0c 06 06 03 6f a0 00 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}