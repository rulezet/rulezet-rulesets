rule Trojan_BAT_Zilla_SLKL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 16 00 00 0a 72 01 00 00 70 6f 17 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 80 01 00 00 04 2a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}