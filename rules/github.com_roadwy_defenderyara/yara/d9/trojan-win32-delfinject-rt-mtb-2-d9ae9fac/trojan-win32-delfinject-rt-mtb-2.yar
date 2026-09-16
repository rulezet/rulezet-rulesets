rule Trojan_Win32_DelfInject_RT_MTB_2{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 2b 50 ?? 8b 45 ?? 8b 00 03 c7 8b 4d ?? 66 8b 09 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 8b 45 ?? 83 c0 02 89 45 ?? 4b 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}