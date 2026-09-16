rule Trojan_BAT_NjRat_NJA_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 0f 00 00 00 26 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 08 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 14 14 14 17 28 ?? ?? ?? 0a 26 dd ?? ?? ?? 00 } 		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}