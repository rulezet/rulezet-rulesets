rule Trojan_Linux_Flooder_I_MTB{
	meta:
		description = "Trojan:Linux/Flooder.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 70 65 72 66 6f 72 6d 48 54 54 50 46 6c 6f 6f 64 } 		$a_01_1 = {54 43 50 66 6c 6f 6f 64 41 74 74 61 63 6b } 		$a_01_2 = {70 65 72 66 6f 72 6d 47 52 45 46 6c 6f 6f 64 } 		$a_01_3 = {6d 61 69 6e 2e 75 64 70 73 6d 61 72 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}