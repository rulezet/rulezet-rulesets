rule Trojan_BAT_SystemBC_psyA_MTB_2{
	meta:
		description = "Trojan:BAT/SystemBC.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 5b 00 00 70 28 08 00 00 0a 19 6f 09 00 00 0a 28 17 00 00 0a 8c 14 00 00 01 28 18 00 00 0a 28 03 00 00 06 25 28 19 00 00 0a 28 1a 00 00 0a 72 b7 00 00 70 6f 1b 00 00 0a 72 c7 00 00 70 20 00 01 00 00 14 14 17 8d 01 00 00 01 25 16 02 a2 6f 1c 00 00 0a 26 de 07 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}