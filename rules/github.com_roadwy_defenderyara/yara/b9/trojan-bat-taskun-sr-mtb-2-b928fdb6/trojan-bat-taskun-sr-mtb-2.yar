rule Trojan_BAT_Taskun_SR_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 11 0d 11 0f 91 6f 96 00 00 0a 11 0e 11 0f 58 13 0e 11 0f 17 58 13 0f 11 0f 11 09 32 e2 } 		$a_01_1 = {43 61 6c 63 75 6c 61 64 6f 72 61 43 69 65 6e 74 69 66 69 63 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}