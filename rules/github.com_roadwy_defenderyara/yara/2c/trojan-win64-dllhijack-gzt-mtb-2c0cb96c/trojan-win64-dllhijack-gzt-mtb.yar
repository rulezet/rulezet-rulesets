rule Trojan_Win64_DllHijack_GZT_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f b7 44 86 df 14 a2 5a 6a aa 00 2f 5b 33 f4 20 d1 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}