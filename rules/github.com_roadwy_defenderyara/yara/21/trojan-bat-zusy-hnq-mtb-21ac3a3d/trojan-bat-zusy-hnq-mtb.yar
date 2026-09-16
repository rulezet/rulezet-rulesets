rule Trojan_BAT_Zusy_HNQ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 00 00 00 [0-04] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f [0-85] 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c [0-08] 2e 00 62 00 61 00 74 00 00 0f 43 00 4d 00 44 00 2e 00 65 00 78 00 65 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}