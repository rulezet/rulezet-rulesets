rule Trojan_Win64_BazarLoader_QV_MTB_4{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 85 7e 01 00 00 8a 8d 7f 01 00 00 88 ca 80 f2 ff 41 88 c0 41 30 d0 41 20 c0 88 c2 80 f2 ff 41 88 c9 41 20 d1 80 f1 ff 20 c8 41 08 c1 44 88 c0 34 ff 44 88 c9 80 f1 ff b2 01 80 f2 01 41 88 c2 41 80 e2 ff 41 20 d0 41 88 cb 41 80 e3 ff 41 20 d1 45 08 c2 45 08 cb 45 30 da 08 c8 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}