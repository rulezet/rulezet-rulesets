rule Trojan_Win64_Lazy_MK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 ba 00 10 00 00 81 e1 ff 0f 00 00 2b d1 48 8b 4f 10 3b d6 0f 4c f2 48 83 64 24 48 00 80 7f 20 00 4c 63 c6 } 	condition:
		((#a_01_0  & 1)*35) >=35
 
}