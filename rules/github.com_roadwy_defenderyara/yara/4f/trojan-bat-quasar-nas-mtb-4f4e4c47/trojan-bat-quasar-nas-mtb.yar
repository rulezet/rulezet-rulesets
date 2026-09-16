rule Trojan_BAT_Quasar_NAS_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {95 11 0d 1d 95 5a 9e 11 17 20 ?? ?? ?? 44 5a 20 ?? ?? ?? 4c 61 38 ?? ?? ?? ff 11 0c 1e 11 0c 1e 95 11 0d 1e 95 } 		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 33 46 2f 43 6f 6e 61 72 69 } 		$a_01_2 = {52 00 78 00 4c 00 48 00 58 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}