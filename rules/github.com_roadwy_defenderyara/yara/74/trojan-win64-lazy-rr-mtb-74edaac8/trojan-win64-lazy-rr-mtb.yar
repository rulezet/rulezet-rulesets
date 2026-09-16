rule Trojan_Win64_Lazy_RR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 31 f6 41 c1 c6 08 45 01 f5 44 31 e8 c1 c0 07 45 01 d1 45 31 cf 41 c1 c7 10 44 01 ff 41 31 fa 41 c1 c2 0c 45 01 d1 44 89 4c 24 28 } 		$a_01_1 = {63 6f 64 65 63 63 65 72 74 38 34 34 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}