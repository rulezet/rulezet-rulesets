rule Trojan_Win32_VBInject_CB_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 33 c0 8a c1 8b 4d ?? 66 89 04 79 8b 45 ?? 8b 00 8b 58 ?? 8b 48 ?? 2b cb 8d 04 11 8b 4d ?? 66 8b 1c 79 66 03 1c 71 66 83 e3 0f 79 ?? 66 4b 66 83 cb f0 66 43 0f bf db 8a 0c 59 30 08 03 95 ?? ?? ?? ?? eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}