rule Trojan_Win64_Tedy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 48 33 c1 41 02 c9 80 e1 } 		$a_01_1 = {48 8b d0 0f b6 c9 48 d3 c2 48 33 c2 } 	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}