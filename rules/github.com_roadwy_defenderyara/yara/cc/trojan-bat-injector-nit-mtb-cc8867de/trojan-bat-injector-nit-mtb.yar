rule Trojan_BAT_Injector_NIT_MTB{
	meta:
		description = "Trojan:BAT/Injector.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 1d 00 00 70 28 ?? 00 00 0a 72 31 00 00 70 72 45 00 00 70 28 ?? 00 00 06 00 02 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 15 28 ?? 00 00 0a 00 2a } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}