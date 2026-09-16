rule Trojan_BAT_AgentTesla_NTM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 09 00 00 fe 0c 04 00 6f ?? ?? ?? 0a fe 0c 00 00 61 fe 0e 05 00 fe 0c 02 00 fe 0c 05 00 fe 0c 01 00 61 fe 09 01 00 fe 0c 04 00 fe 0c 03 00 5d 6f ?? ?? ?? 0a 61 d1 fe 0e 06 00 fe 0d 06 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 02 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 00 fe 09 00 00 6f ?? ?? ?? 0a 3f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}