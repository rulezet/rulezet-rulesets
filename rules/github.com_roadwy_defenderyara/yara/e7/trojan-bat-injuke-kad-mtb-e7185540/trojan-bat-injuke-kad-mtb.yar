rule Trojan_BAT_Injuke_KAD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {54 42 44 74 53 54 61 65 6c 6d 54 6f 46 72 61 65 2e 64 6c 6c } 		$a_80_1 = {51 5a 74 63 5a 54 72 4e 6a 6a 67 74 2e 64 6c 6c } 		$a_80_2 = {77 70 72 57 7a 70 46 49 63 44 46 48 2e 64 6c 6c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}