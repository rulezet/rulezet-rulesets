rule Trojan_BAT_CryptInject_MBKS_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 5e 00 41 00 44 00 5e 00 5e 00 41 00 5f 00 5e 00 5e 00 41 00 50 00 37 00 37 00 59 00 5e 00 43 00 34 00 5e 00 5e 00 5e 00 5e 00 5e 00 41 00 43 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e } 		$a_01_1 = {20 00 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 4c 00 75 00 75 00 4e 00 69 00 65 00 6d 00 2e 00 43 00 6f 00 75 00 70 00 6f 00 6e 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}