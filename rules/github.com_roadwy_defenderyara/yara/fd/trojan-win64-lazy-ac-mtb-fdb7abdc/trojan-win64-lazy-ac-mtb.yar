rule Trojan_Win64_Lazy_AC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 01 0f 28 d6 0f af c1 0f 28 c3 f2 0f 59 c5 83 c1 02 0f 57 df f2 0f 58 e0 66 0f 6e c8 f3 0f e6 c9 f2 0f 5e d1 f2 0f 59 ea 48 83 ea 01 75 d0 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}