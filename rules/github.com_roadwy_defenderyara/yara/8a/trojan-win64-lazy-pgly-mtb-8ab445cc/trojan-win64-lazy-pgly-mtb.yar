rule Trojan_Win64_Lazy_PGLY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {cb b5 d9 4b df e6 9c 43 08 a2 00 31 0b ea 2b 2a 49 2d a7 e1 ff fa 12 c9 e9 97 e6 db 9f 8e e2 1f 12 3d 12 cb 15 a3 a7 c0 9d 66 fd } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}