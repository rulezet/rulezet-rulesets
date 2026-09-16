rule Trojan_BAT_AgentTesla_SML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 13 0a 16 13 10 2b 14 11 0a 11 10 5a 1d 58 20 00 01 00 00 5d 26 11 10 17 58 13 10 11 10 19 32 e7 } 		$a_81_1 = {47 35 5a 50 45 46 38 36 35 48 43 38 38 47 30 47 43 44 34 47 44 30 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}