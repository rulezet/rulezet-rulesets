rule Trojan_Win32_Lazy_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 0f b6 c4 c1 e0 08 09 d0 0f b6 d7 c1 e2 10 09 c2 0f b6 c3 c1 e0 18 09 d0 66 0f 6e c8 66 0f ef c8 66 ?? ?? ?? ?? 46 83 fe 3c } 		$a_01_1 = {8a 1c 82 88 1c 81 8a 5c 82 01 88 5c 81 01 8a 5c 82 02 88 5c 81 02 8a 5c 82 03 88 5c 81 03 40 83 f8 08 75 dc } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}