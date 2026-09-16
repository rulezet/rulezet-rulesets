rule Trojan_BAT_Jalapeno_NF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 0b 11 26 58 1d 11 22 58 61 d2 13 1a } 		$a_01_1 = {11 19 18 91 11 19 19 91 1f 10 62 60 11 19 16 91 1e 62 60 11 19 17 91 1f 18 62 60 02 65 61 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}