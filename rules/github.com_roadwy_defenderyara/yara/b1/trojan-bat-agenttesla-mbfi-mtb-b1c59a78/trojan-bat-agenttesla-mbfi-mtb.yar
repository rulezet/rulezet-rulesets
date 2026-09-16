rule Trojan_BAT_AgentTesla_MBFI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 0a 11 05 1f 45 93 11 05 1f 45 93 59 13 04 2b c0 03 04 61 1f 10 59 06 61 } 		$a_01_1 = {6a 55 73 47 69 44 33 75 73 68 31 75 42 79 59 4f 34 4a 00 66 65 4a 6d 55 30 30 4b 64 00 63 46 6f 77 } 		$a_01_2 = {42 65 6e 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}