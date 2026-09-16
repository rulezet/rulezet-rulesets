rule Trojan_Win64_DllHijack_GZT_MTB_2{
	meta:
		description = "Trojan:Win64/DllHijack.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 5d 9c 31 66 ab b6 2a 8b 64 ac 4a } 		$a_01_1 = {b0 02 6b 28 d4 2a 0e 31 d0 } 		$a_80_2 = {65 71 66 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}