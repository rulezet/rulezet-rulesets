rule Trojan_Win64_Lazy_AHI_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f ef 85 d0 00 00 00 4c 89 bd e0 00 00 00 48 89 9d e8 00 00 00 66 0f ef 8d e0 00 00 00 66 0f 7f 8d 40 03 00 00 66 0f 7f 85 30 03 00 00 ff d0 } 		$a_03_1 = {49 33 c8 48 bf ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c7 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 48 63 c1 48 8b cb 4c 89 84 c5 50 02 00 00 48 8b 84 c5 50 02 00 00 ff d0 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}