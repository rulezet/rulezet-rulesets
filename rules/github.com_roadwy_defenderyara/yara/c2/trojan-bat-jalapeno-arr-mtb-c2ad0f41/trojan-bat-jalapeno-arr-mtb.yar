rule Trojan_BAT_Jalapeno_ARR_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f d1 0b 07 08 61 06 11 05 1f 0f 5f 93 61 d1 0b 06 07 1f 0f 5f 93 0c 07 1a 63 } 		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } 	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}