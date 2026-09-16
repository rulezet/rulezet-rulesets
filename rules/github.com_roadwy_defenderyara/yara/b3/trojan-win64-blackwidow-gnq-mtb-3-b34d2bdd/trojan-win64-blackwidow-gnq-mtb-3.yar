rule Trojan_Win64_BlackWidow_GNQ_MTB_3{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 0f b6 44 0c ?? 43 32 44 08 ?? 41 88 41 ?? 49 ff cb 0f 85 } 		$a_03_1 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 0f af cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}