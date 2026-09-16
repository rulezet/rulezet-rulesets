rule Trojan_BAT_AgentTesla_NAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 07 1f 10 5d 91 61 07 20 ?? ?? ?? 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d4 } 		$a_01_1 = {53 70 6c 69 74 } 		$a_01_2 = {43 6f 6e 63 61 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}