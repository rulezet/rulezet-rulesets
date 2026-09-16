rule Trojan_BAT_AgentTesla_EM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 06 8e 69 17 59 0d 2b 1a 08 06 09 9a 07 09 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 09 17 59 0d 09 16 2f e2 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_4 = {52 65 70 6c 61 63 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}