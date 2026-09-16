rule Trojan_BAT_AgentTesla_NZ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {9a 0c 08 19 8d [0-04] 25 16 7e [0-04] a2 25 17 7e [0-04] a2 25 18 72 [0-04] a2 28 [0-04] 26 20 [0-04] 0a 2b 90 09 0e 00 28 [0-04] 0b 07 6f [0-04] 1f } 		$a_02_1 = {10 04 02 0e 04 28 [0-04] 28 [0-04] 26 2a 90 09 13 00 28 [0-05] 02 0e ?? 28 [0-04] 28 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}