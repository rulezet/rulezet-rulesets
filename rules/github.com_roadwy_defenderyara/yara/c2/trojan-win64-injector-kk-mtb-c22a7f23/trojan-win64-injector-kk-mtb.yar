rule Trojan_Win64_Injector_KK_MTB{
	meta:
		description = "Trojan:Win64/Injector.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 94 04 8e 00 00 00 89 d7 40 f6 df 19 c9 83 e1 44 31 ca 41 88 14 02 48 ff c0 48 83 f8 12 } 		$a_01_1 = {0f b7 c0 49 ff c3 31 d0 c1 ea 10 69 c0 3b 9f 5d 04 31 c2 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}