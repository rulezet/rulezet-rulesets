rule Trojan_BAT_Taskun_SR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0c 94 13 0d 11 04 11 0d 6c 58 13 04 11 0c 17 58 13 0c 11 0c 11 0b } 		$a_81_1 = {41 6d 69 72 43 61 6c 65 6e 64 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}