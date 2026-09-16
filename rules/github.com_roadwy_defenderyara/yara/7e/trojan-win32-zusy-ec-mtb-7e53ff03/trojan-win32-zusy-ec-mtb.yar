rule Trojan_Win32_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 c0 10 2b c1 c1 e8 10 40 c3 33 c0 40 2b c6 2b c2 c3 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}