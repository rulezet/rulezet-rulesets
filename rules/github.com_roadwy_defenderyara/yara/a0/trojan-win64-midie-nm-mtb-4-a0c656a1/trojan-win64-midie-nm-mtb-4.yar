rule Trojan_Win64_Midie_NM_MTB_4{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 7c 24 ?? 00 49 0f 44 d6 4c 8d 44 24 ?? 4c 8d 7c 24 ?? 4c 89 f9 e8 21 f3 ff ff 4c 8d a4 24 } 		$a_03_1 = {48 89 ce 0f b6 81 ?? 00 00 00 88 91 ?? 00 00 00 48 8d 0d 67 01 00 00 48 63 04 81 48 01 c8 ff e0 0f b6 c2 ff c8 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}