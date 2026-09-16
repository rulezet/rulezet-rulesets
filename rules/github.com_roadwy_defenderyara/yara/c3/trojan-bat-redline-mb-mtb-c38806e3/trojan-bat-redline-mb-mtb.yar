rule Trojan_BAT_RedLine_MB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 16 0c 2b 3e 03 08 03 8e 69 5d 17 58 17 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}