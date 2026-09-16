rule Trojan_BAT_Stealer_SGE_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 35 65 39 31 38 61 62 33 2d 31 39 64 34 2d 34 37 63 34 2d 62 32 35 65 2d 62 39 38 35 62 39 38 36 37 34 61 35 } 		$a_01_1 = {6c 00 75 00 6e 00 61 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 2e 00 6a 00 73 00 6f 00 6e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}