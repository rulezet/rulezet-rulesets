rule Trojan_BAT_LummaC_ALU_MTB_3{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 } 		$a_03_1 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 66 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}