rule Trojan_BAT_AveMaria_NE_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 72 01 00 00 70 28 ?? ?? ?? 06 0a 06 73 ?? ?? ?? 0a 0b 00 73 04 00 00 0a 0c 00 07 16 73 05 00 00 0a 73 06 00 00 0a 0d } 		$a_01_1 = {72 00 61 00 6d 00 61 00 6e 00 6b 00 75 00 6d 00 61 00 72 00 79 00 6e 00 72 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}