rule Trojan_BAT_Nancat_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Nancat.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 06 1f 16 5d 91 13 0c } 		$a_01_1 = {11 0b 11 0c 61 13 0e } 		$a_01_2 = {11 01 11 09 11 0f 11 07 5d d2 9c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}