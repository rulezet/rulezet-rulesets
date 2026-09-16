rule Trojan_BAT_AgentTesla_ABA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 1d 09 6f [0-03] 0a 13 07 08 11 07 07 02 11 07 18 5a 18 6f [0-03] 0a 6f [0-03] 0a 9c 09 6f } 		$a_01_1 = {45 6c 72 65 64 6b 63 63 6a 72 6e 65 6d 71 71 71 69 64 6f 68 6b } 		$a_01_2 = {47 65 74 42 75 66 66 65 72 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}