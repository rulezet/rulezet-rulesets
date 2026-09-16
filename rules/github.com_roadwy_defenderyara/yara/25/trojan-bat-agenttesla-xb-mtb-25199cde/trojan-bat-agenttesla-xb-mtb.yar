rule Trojan_BAT_AgentTesla_XB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 02 17 8d ?? ?? ?? 01 25 16 1f 2d 9d 6f ?? ?? ?? 0a 0b 00 07 0c 16 0d 2b 1c 08 09 9a 13 04 00 06 11 04 1f 10 28 ?? ?? ?? 0a d1 6f ?? ?? ?? 0a 26 00 09 17 58 0d } 		$a_01_1 = {48 65 78 32 53 74 72 69 6e 67 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}