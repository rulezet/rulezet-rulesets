rule Trojan_BAT_Webshell_AWB_MTB{
	meta:
		description = "Trojan:BAT/Webshell.AWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 11 05 11 04 09 08 02 6f ?? 00 00 0a 28 ?? 00 00 0a 74 ?? 00 00 01 7b ?? 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 25 19 07 a2 26 07 00 02 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}