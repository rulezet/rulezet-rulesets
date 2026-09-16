rule Trojan_BAT_Lazy_MX_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 6f 1f 00 00 0a 08 6f 20 00 00 0a 28 21 00 00 0a 0b de 14 } 		$a_01_1 = {11 10 72 8b 01 00 70 6f 1a 00 00 0a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}