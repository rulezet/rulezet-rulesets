rule Trojan_Win64_LummaStealer_GAPO_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {bf 05 a1 f3 44 08 56 c7 26 21 2d bd b4 9a 34 65 eb 5b 2f } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}