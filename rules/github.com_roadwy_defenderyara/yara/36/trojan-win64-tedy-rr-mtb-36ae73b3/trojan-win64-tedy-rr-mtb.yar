rule Trojan_Win64_Tedy_RR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {94 33 01 00 b5 33 01 00 d3 33 01 00 f1 33 01 00 0f 34 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}