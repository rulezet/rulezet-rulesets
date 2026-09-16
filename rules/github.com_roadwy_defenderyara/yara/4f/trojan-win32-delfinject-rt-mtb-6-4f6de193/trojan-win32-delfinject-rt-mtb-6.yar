rule Trojan_Win32_DelfInject_RT_MTB_6{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b 43 ?? 99 03 04 24 13 54 24 ?? 83 c4 08 89 45 ?? 8b 45 ?? 89 48 } 		$a_03_1 = {0f b7 03 c1 e8 0c 83 f8 03 75 ?? 8b 45 ?? 8b d6 2b 50 ?? 8b 45 ?? 8b 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 83 c3 02 4f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}