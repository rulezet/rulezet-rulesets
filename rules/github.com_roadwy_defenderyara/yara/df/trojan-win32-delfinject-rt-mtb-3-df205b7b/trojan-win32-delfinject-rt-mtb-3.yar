rule Trojan_Win32_DelfInject_RT_MTB_3{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 c4 f9 74 ?? 8b 4d ?? 8b 49 ?? 8b 75 ?? 8b 76 ?? 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 ?? 8b 40 ?? 01 01 83 03 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}