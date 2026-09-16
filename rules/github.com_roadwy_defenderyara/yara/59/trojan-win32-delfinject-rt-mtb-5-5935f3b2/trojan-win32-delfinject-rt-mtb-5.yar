rule Trojan_Win32_DelfInject_RT_MTB_5{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 10 00 00 50 8d 04 9b 8b 44 c6 ?? 03 45 ?? 50 e8 } 		$a_03_1 = {f6 c4 f0 74 ?? 8b 5d ?? 8b 5b ?? 8b 75 ?? 8b 76 ?? 03 1e 66 25 ff 0f 0f b7 c0 03 d8 8b 45 ?? 8b 40 ?? 01 03 83 01 02 4a 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}