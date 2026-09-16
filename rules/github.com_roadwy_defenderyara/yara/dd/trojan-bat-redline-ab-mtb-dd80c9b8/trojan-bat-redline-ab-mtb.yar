rule Trojan_BAT_Redline_AB_MTB{
	meta:
		description = "Trojan:BAT/Redline.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 25 00 00 01 0a 02 1b 06 16 02 8e 69 1b 59 28 63 00 00 0a 06 16 14 28 33 00 00 06 0b 25 03 6f 64 00 00 0a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}