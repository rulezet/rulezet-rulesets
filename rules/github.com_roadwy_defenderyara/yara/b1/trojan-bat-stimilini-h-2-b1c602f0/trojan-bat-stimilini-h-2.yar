rule Trojan_BAT_Stimilini_H_2{
	meta:
		description = "Trojan:BAT/Stimilini.H,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65 } 		$a_01_1 = {2e 49 74 65 6d 3e 3e 2e 47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } 		$a_01_2 = {2e 49 74 65 6d 3e 3e 2e 67 65 74 5f 43 75 72 72 65 6e 74 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}