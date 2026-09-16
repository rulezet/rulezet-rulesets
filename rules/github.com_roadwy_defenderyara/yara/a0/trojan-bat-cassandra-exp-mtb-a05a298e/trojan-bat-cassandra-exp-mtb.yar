rule Trojan_BAT_Cassandra_EXP_MTB{
	meta:
		description = "Trojan:BAT/Cassandra.EXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {44 72 69 76 65 72 46 69 78 20 50 72 6f 2e 64 6c 6c } 		$a_81_1 = {53 79 73 74 65 6d 20 64 72 69 76 65 72 20 72 65 70 61 69 72 20 75 74 69 6c 69 74 79 } 		$a_81_2 = {32 2e 33 2e 31 2e 37 38 39 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}