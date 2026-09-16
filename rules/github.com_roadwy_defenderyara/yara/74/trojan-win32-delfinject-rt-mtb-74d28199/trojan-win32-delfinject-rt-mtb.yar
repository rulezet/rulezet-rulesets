rule Trojan_Win32_DelfInject_RT_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 08 f6 c5 f0 74 ?? 8b 45 ?? 8b 00 03 05 ?? ?? ?? ?? 66 81 e1 ff 0f 0f b7 c9 03 c1 8b 0d ?? ?? ?? ?? 01 08 83 45 ?? 02 4a 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}