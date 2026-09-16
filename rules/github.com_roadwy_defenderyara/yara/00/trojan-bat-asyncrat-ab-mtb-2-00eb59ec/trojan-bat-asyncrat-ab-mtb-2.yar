rule Trojan_BAT_AsyncRAT_AB_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 a6 00 00 0a 1f 20 8d 58 00 00 01 25 d0 8e 01 00 04 28 a7 00 00 0a 28 30 01 00 06 28 a8 00 00 0a 72 3e 27 00 70 72 01 00 00 70 6f a9 00 00 0a } 		$a_01_1 = {09 11 04 06 11 04 8f 58 00 00 01 72 70 27 00 70 28 ad 00 00 0a a2 11 04 17 58 13 04 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}