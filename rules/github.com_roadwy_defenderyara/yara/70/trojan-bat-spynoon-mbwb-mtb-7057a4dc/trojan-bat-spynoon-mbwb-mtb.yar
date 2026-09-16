rule Trojan_BAT_SpyNoon_MBWB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MBWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0c 20 00 c0 00 00 0d 07 08 09 } 		$a_01_1 = {4c 00 6f 00 61 00 64 00 } 		$a_01_2 = {64 00 72 00 63 } 		$a_01_3 = {47 65 74 50 69 78 65 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}