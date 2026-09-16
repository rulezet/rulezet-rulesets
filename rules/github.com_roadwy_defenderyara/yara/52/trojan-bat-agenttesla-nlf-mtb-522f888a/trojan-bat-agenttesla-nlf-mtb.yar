rule Trojan_BAT_AgentTesla_NLF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {7b 1a 00 00 04 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 07 16 07 8e 69 6f ?? ?? ?? 0a } 		$a_01_1 = {31 66 73 69 78 64 74 } 		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 5a 61 6d 65 74 6b 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}