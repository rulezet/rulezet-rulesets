rule Trojan_BAT_Ursu_AU_MTB_2{
	meta:
		description = "Trojan:BAT/Ursu.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 17 12 00 15 6a 16 28 ?? ?? ?? 0a 17 8d 0c 00 00 01 0d 09 16 17 9e 09 28 ?? ?? ?? 0a 06 72 e9 00 00 70 15 16 28 ?? ?? ?? 0a 0b 19 08 } 		$a_01_1 = {62 00 69 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}