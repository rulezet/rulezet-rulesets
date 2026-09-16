rule Trojan_BAT_AgentTesla_NA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8f 0b 00 00 01 25 71 ?? 00 00 01 fe ?? ?? 00 fe ?? ?? 00 20 ?? 00 00 00 5d 91 61 d2 81 ?? 00 00 01 20 ?? 00 00 00 fe ?? ?? 00 00 fe ?? ?? 00 20 ?? 00 00 00 fe 01 39 ?? 00 00 00 } 		$a_01_1 = {46 6c 61 6d 65 41 73 73 65 6d 62 6c 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}