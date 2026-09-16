rule VirTool_BAT_CryptInject_MTB_2{
	meta:
		description = "VirTool:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 66 75 63 6b 2e 65 78 65 } 		$a_01_1 = {49 00 6e 00 6a 00 65 00 63 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}