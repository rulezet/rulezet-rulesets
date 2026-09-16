rule Trojan_BAT_KillMBR_ARAX_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 07 8e 69 6f ?? ?? ?? 0a 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 0c 09 08 28 ?? ?? ?? 0a 0d 11 04 17 58 13 04 11 04 1f 0e 32 d7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}