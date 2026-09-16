rule Trojan_BAT_Disstl_ADI_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 28 ?? ?? ?? 0a a2 25 18 72 50 01 00 70 a2 25 19 02 7b 05 00 00 04 a2 25 1a 72 54 01 00 70 a2 28 ?? ?? ?? 0a 0c 07 06 } 		$a_01_1 = {5c 64 65 62 75 67 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 50 63 43 6c 65 61 6e 65 72 5c 50 63 43 6c 65 61 6e 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 63 43 6c 65 61 6e 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}