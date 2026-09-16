rule Trojan_BAT_Heracles_NH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 06 08 06 93 02 7b ?? 01 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}