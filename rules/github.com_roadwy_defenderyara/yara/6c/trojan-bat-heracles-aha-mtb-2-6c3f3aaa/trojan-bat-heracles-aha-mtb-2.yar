rule Trojan_BAT_Heracles_AHA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 34 00 00 01 0a 16 0b 2b 0d 06 07 02 07 91 03 61 d1 9d 07 17 58 0b 07 02 8e 69 32 ed } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}