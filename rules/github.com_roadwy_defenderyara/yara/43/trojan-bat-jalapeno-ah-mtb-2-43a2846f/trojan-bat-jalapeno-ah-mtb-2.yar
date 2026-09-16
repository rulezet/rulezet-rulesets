rule Trojan_BAT_Jalapeno_AH_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 70 64 61 74 65 4b 78 65 50 72 6f 63 65 73 73 4c 69 73 74 } 		$a_01_1 = {67 65 74 5f 4b 78 65 50 72 6f 63 65 73 73 65 73 } 		$a_01_2 = {46 65 74 63 68 41 6e 64 52 75 6e 43 6f 6e 66 69 67 } 		$a_01_3 = {52 65 63 6f 72 64 46 69 72 73 74 52 75 6e 54 69 6d 65 } 		$a_01_4 = {43 68 65 63 6b 46 6f 72 4b 78 65 50 72 6f 63 65 73 73 65 73 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40+(#a_01_4  & 1)*50) >=150
 
}