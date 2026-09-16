rule Trojan_BAT_Remcos_ARC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 18 5b 08 06 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 06 18 58 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}