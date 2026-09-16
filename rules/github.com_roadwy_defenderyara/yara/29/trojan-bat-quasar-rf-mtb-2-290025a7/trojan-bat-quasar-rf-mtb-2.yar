rule Trojan_BAT_Quasar_RF_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 0f 0a 1f 0f 0b 1f 0f 0b 00 07 16 33 05 1f 0f 0b 2b 17 00 12 00 12 01 12 02 12 03 7e ?? ?? ?? ?? 06 97 29 ?? ?? ?? ?? 2b df 00 2a } 		$a_01_1 = {24 35 66 30 64 63 63 63 38 2d 64 36 39 61 2d 34 39 66 38 2d 39 65 36 34 2d 36 31 61 65 37 37 62 66 66 34 38 66 } 		$a_01_2 = {47 00 72 00 61 00 73 00 79 00 61 00 79 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}