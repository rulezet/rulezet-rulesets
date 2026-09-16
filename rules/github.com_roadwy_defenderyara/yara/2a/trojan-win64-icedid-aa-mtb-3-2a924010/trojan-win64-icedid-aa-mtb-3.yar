rule Trojan_Win64_IcedID_AA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 83 e0 01 83 f8 00 41 0f 94 c0 83 f9 0a 41 0f 9c c1 45 88 c2 41 80 f2 ff 45 88 cb 41 80 f3 ff b3 01 80 f3 01 44 88 d6 40 80 e6 ff 41 20 d8 44 88 df 40 80 e7 ff 41 20 d9 44 08 c6 44 08 cf 40 30 fe 45 08 da 41 80 f2 ff 80 cb 01 41 20 da 44 08 d6 40 f6 c6 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f } 		$a_03_1 = {88 c2 80 f2 ff 41 88 c8 41 80 f0 ff 41 b1 01 41 80 f1 01 41 88 d2 41 80 e2 ff 44 20 c8 45 88 c3 41 80 e3 ff 44 20 c9 41 08 c2 41 08 cb 45 30 da 44 08 c2 80 f2 ff 41 80 c9 01 44 20 ca 41 08 d2 41 f6 c2 01 be ?? ?? ?? ?? bf ?? ?? ?? ?? 0f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}