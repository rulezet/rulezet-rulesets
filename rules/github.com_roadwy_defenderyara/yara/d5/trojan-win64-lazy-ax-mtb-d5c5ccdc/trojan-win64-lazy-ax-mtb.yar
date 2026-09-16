rule Trojan_Win64_Lazy_AX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 d0 21 d0 f7 d2 89 d3 31 cb 21 d3 21 d1 09 c1 89 d8 f7 d0 89 ca f7 d2 89 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}