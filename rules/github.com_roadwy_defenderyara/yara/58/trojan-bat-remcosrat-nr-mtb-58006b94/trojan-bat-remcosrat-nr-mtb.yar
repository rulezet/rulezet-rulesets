rule Trojan_BAT_RemcosRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 13 03 20 0e 00 00 00 fe ?? ?? 00 38 ?? ?? ?? ff 16 6a 13 00 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff } 		$a_01_1 = {42 6e 6e 69 79 64 74 64 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}