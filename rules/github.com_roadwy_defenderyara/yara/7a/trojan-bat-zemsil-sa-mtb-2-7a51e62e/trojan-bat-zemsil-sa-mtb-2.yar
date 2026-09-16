rule Trojan_BAT_Zemsil_SA_MTB_2{
	meta:
		description = "Trojan:BAT/Zemsil.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 03 04 06 28 53 00 00 06 00 00 06 17 58 0a 06 02 6f 78 00 00 0a fe 04 0b 07 2d e3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}