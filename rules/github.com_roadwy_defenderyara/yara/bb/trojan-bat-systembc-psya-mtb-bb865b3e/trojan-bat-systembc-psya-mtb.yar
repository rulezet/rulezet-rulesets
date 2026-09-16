rule Trojan_BAT_SystemBC_psyA_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 9a 06 28 82 00 00 0a 39 0b 00 00 00 7e ad 04 00 04 74 71 00 00 01 2a 07 17 58 0b 07 7e ac 04 00 04 8e } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}