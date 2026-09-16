rule Trojan_BAT_Jalapeno_AJL_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 1f 16 5d 91 13 05 02 07 11 04 91 11 05 61 07 11 04 17 58 08 7e ?? 00 00 04 20 61 01 00 00 7e ?? 00 00 04 20 61 01 00 00 91 7e ?? 00 00 04 20 de 00 00 00 91 5a 20 c2 00 00 00 5f 9c 5d 91 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}