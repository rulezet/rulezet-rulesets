rule HackTool_Win64_CoercedPotato_MX_MTB{
	meta:
		description = "HackTool:Win64/CoercedPotato.MX!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 65 72 63 65 64 50 6f 74 61 74 6f } 		$a_01_1 = {45 78 70 6c 6f 69 74 } 		$a_01_2 = {50 72 65 70 6f 75 63 65 } 		$a_01_3 = {48 61 63 6b 30 75 72 61 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}