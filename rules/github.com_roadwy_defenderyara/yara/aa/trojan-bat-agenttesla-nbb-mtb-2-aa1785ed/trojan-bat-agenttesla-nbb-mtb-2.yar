rule Trojan_BAT_AgentTesla_NBB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 53 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0c 02 0d 08 09 16 09 8e b7 6f ?? 00 00 0a } 		$a_01_1 = {74 61 73 6b 73 68 6f 73 74 77 } 		$a_01_2 = {58 00 30 00 4b 00 4d 00 44 00 67 00 64 00 37 00 44 00 57 00 6e 00 48 00 54 00 56 00 30 00 41 00 71 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}