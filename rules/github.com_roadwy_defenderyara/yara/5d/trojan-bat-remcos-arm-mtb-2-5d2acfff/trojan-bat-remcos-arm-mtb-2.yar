rule Trojan_BAT_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 22 2b 2f 11 07 11 06 8e 69 5d 13 23 11 06 11 23 11 21 11 22 91 9c 03 11 21 11 22 91 6f ?? 00 00 0a 11 07 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}