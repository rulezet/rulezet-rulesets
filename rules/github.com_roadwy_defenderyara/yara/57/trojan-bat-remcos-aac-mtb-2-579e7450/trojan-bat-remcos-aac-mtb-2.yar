rule Trojan_BAT_Remcos_AAC_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.AAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 2b 42 03 08 03 8e 69 5d 7e 91 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 d0 00 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}