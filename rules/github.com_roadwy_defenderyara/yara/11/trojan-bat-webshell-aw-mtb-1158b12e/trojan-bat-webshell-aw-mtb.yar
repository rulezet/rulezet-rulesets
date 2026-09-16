rule Trojan_BAT_Webshell_AW_MTB{
	meta:
		description = "Trojan:BAT/Webshell.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 11 05 02 6f 16 00 00 0a 6f 4c 00 00 0a 26 11 05 11 04 6f 4c 00 00 0a 26 11 05 09 6f 4c 00 00 0a 26 11 05 6f 4d 00 00 0a 26 11 04 6f 4e 00 00 0a 13 06 02 6f 16 00 00 0a 6f 4f 00 00 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}