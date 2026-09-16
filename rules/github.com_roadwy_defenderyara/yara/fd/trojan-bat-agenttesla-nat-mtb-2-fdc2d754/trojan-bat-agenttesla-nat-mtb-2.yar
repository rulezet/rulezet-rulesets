rule Trojan_BAT_AgentTesla_NAT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f ?? ?? ?? 0a 0c 06 08 28 ?? ?? ?? 0a 07 59 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0a 11 04 17 58 13 04 11 04 09 6f ?? ?? ?? 0a 3f } 		$a_01_1 = {32 61 62 39 39 63 66 2d 38 65 33 35 2d 34 35 33 65 2d 38 38 64 36 2d 34 33 64 31 36 30 30 31 65 64 35 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}