rule Trojan_Win64_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 29 8b 05 ?? ?? ?? ?? 65 48 8b 0c 25 ?? ?? ?? ?? 48 8b 04 c1 4c 8b 80 ?? ?? ?? ?? 48 8b 0d 46 b0 2e 00 31 d2 } 		$a_01_1 = {6d 61 6e 69 6e 74 65 72 6e 6d 65 6e 74 73 72 69 6a 69 62 6d 61 6e 69 6e 74 65 72 6e 6d 65 6e 74 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}