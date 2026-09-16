rule Trojan_BAT_AgentTesla_VN_MTB_17{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 06 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 28 ?? ?? ?? 0a 9c 00 06 15 58 0a 06 16 fe ?? 16 fe ?? 0b 07 2d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}