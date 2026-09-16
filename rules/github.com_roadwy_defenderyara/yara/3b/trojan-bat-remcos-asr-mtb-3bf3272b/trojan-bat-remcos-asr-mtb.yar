rule Trojan_BAT_Remcos_ASR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 03 00 00 01 0d 16 13 04 2b 1c 09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}