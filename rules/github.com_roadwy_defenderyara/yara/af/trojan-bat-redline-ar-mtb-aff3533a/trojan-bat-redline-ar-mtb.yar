rule Trojan_BAT_Redline_AR_MTB{
	meta:
		description = "Trojan:BAT/Redline.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 05 48 00 70 2b 04 2b 09 de 0d 28 ?? ?? ?? 06 2b f5 0a 2b f4 26 de e7 2b 01 2a 06 2b fc } 		$a_01_1 = {75 00 70 00 64 00 61 00 74 00 65 00 61 00 64 00 6f 00 62 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}