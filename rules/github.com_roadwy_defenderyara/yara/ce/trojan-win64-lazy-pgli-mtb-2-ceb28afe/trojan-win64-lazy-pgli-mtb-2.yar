rule Trojan_Win64_Lazy_PGLI_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.PGLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 ca 89 d0 34 01 08 c2 80 f2 01 89 c1 20 d1 30 c2 08 ca 89 d0 34 01 89 d1 89 f3 40 20 f2 40 80 f6 01 40 20 f1 20 c3 08 cb 80 f3 01 40 08 f3 89 d9 80 f1 01 40 20 c6 40 08 f2 89 d0 34 01 20 da 20 c1 08 d1 89 da 20 c2 30 d8 08 d0 89 c2 30 ca a8 01 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}