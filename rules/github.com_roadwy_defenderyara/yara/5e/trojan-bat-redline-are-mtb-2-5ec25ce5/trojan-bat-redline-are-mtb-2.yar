rule Trojan_BAT_Redline_ARE_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 09 2b 70 11 08 11 09 9a 0d 7e 2e 00 00 0a 13 04 09 6f 2f 00 00 0a 13 05 11 05 6f 30 00 00 0a 13 06 16 13 07 2b 38 11 04 11 06 11 07 8f 2d 00 00 01 28 31 00 00 0a 28 32 00 00 0a 13 04 11 07 11 06 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}