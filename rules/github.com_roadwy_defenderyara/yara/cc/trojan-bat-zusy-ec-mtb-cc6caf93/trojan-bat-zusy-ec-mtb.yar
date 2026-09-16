rule Trojan_BAT_Zusy_EC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 1f 2d 9d 6f a4 00 00 0a 0c 08 16 9a 28 16 00 00 0a 08 17 9a 08 18 9a } 		$a_01_1 = {43 65 6e 73 6f 49 42 47 45 2e 52 65 6d 6f 76 65 43 61 64 61 73 74 72 6f 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}