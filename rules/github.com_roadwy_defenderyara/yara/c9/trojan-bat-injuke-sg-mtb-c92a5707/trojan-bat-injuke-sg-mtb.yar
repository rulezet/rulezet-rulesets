rule Trojan_BAT_Injuke_SG_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 8b 00 00 70 28 1b 00 00 0a 72 95 00 00 70 28 1c 00 00 0a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}