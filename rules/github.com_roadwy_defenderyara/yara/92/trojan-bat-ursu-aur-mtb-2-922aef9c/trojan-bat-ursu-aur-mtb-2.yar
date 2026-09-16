rule Trojan_BAT_Ursu_AUR_MTB_2{
	meta:
		description = "Trojan:BAT/Ursu.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f ?? ?? ?? 0a 13 05 06 12 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 11 04 17 58 13 04 11 04 07 31 dc } 		$a_01_1 = {74 00 65 00 73 00 74 00 53 00 74 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}