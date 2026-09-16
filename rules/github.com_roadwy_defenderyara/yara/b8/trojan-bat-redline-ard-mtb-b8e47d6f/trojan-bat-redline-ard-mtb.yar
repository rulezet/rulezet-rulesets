rule Trojan_BAT_Redline_ARD_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 06 0b 1b 8d d1 00 00 01 0c 16 0d 2b 0e 09 06 08 09 1b 09 59 6f 47 00 00 0a 58 0d 09 1b 32 ee } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}