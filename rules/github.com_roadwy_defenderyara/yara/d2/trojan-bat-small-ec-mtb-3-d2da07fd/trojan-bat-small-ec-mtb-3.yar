rule Trojan_BAT_Small_EC_MTB_3{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d cd } 		$a_81_1 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 69 73 61 62 6c 65 64 20 41 4d 53 49 21 } 		$a_81_2 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 75 6e 68 6f 6f 6b 65 64 20 45 54 57 21 } 		$a_81_3 = {5b 2b 5d 20 55 52 4c 2f 50 41 54 48 } 	condition:
		((#a_01_0  & 1)*8+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=11
 
}