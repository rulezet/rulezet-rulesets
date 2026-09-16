rule Trojan_Win32_DelfInject_RF_MTB_2{
	meta:
		description = "Trojan:Win32/DelfInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f2 3f 8d 91 ?? ?? ?? ?? 81 f3 51 03 00 00 8b 45 ?? 8b 40 ?? 03 45 ?? 89 45 ?? 8d 14 03 29 d1 83 f2 3f } 		$a_03_1 = {f6 c4 f0 74 ?? 8b 5d ?? 8b 5b ?? 8b 75 ?? 8b 76 ?? 03 1e 66 25 ff 0f 0f b7 c0 03 d8 8b 45 ?? 8b 40 ?? 01 03 83 01 02 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}