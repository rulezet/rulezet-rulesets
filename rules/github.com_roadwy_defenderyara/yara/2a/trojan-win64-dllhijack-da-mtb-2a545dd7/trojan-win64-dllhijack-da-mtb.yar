rule Trojan_Win64_DllHijack_DA_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 01 48 8d 49 01 04 4b ff c2 34 3f 2c 4b 88 41 ff 3b 54 24 48 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}