rule Trojan_BAT_Marsilla_SK_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilla.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 18 5b 07 11 05 18 6f 36 00 00 0a 1f 10 28 37 00 00 0a 9c 11 05 18 d6 13 05 11 05 11 04 31 de } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}