rule Trojan_BAT_SorvePotel_GMT_MTB{
	meta:
		description = "Trojan:BAT/SorvePotel.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 1b 00 fe 0c 17 00 46 fe 0c 02 00 61 52 fe 0c 17 00 20 01 00 00 00 58 fe 0e 17 00 fe 0c 1b 00 20 01 00 00 00 58 fe 0e 1b 00 } 		$a_01_1 = {43 43 53 59 53 43 41 4c 4c 4d 6b 72 65 66 61 6e 79 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}