rule Trojan_Win64_Lazy_PGLY_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 a3 fb a6 08 f4 81 71 8d b2 05 1f ae 81 82 69 51 7b ea 61 3d a6 fb 9e 0d 6f b8 8e 3b 20 b5 0f d1 4b 07 69 c5 34 df f5 2a 75 60 e3 d0 54 83 fa 36 a5 d1 84 99 ee 1e 75 78 04 b1 39 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}