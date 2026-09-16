rule Trojan_Win32_VBInject_CB_MTB{
	meta:
		description = "Trojan:Win32/VBInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 8b cf 66 83 c1 06 66 0f b6 04 02 66 99 0f 80 ?? ?? ?? ?? 66 f7 f9 66 8b ca 8b 13 8b 42 0c 8b 95 ?? ?? ?? ?? 66 0f b6 04 10 33 c8 ff 15 ?? ?? ?? ?? 8b 0b 8b 51 0c 88 04 32 b8 01 00 00 00 66 03 c7 bf 02 00 00 00 0f 80 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}