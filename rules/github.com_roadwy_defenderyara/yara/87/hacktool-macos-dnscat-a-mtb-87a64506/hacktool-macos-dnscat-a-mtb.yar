rule HackTool_MacOS_Dnscat_A_MTB{
	meta:
		description = "HackTool:MacOS/Dnscat.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 72 5f 64 6e 73 2e 63 } 		$a_01_1 = {64 6e 73 5f 74 6f 5f 70 61 63 6b 65 74 } 		$a_01_2 = {74 75 6e 6e 65 6c 5f 64 72 69 76 65 72 73 2f 64 72 69 76 65 72 5f 64 6e 73 2e 63 } 		$a_01_3 = {64 72 69 76 65 72 73 2f 63 6f 6d 6d 61 6e 64 2f 63 6f 6d 6d 61 6e 64 5f 70 61 63 6b 65 74 2e 63 } 		$a_01_4 = {5f 63 6f 6e 74 72 6f 6c 6c 65 72 5f 6b 69 6c 6c 5f 61 6c 6c 5f 73 65 73 73 69 6f 6e 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}