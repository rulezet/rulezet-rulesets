rule Trojan_BAT_Purelog_MX_MTB_2{
	meta:
		description = "Trojan:BAT/Purelog.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 05 16 11 06 6f 0d 00 00 0a 38 00 00 00 00 11 04 11 05 } 		$a_01_1 = {11 04 11 05 16 11 05 8e 69 6f 0b 00 00 0a 25 13 06 16 3d 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}