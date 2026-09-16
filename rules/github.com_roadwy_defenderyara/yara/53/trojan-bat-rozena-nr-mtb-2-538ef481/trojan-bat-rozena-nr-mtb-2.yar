rule Trojan_BAT_Rozena_NR_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 28 28 2a 00 00 0a 6e 06 1f 2c 28 ?? ?? ?? 0a 6e 0c 28 ?? ?? ?? 06 6e 08 28 ?? ?? ?? 06 6e 0c 20 ?? ?? ?? 00 6a 5a 08 20 ?? ?? ?? 00 6a 5a } 		$a_01_1 = {43 53 68 61 72 70 4c 6f 61 64 65 72 41 45 53 6b 65 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}