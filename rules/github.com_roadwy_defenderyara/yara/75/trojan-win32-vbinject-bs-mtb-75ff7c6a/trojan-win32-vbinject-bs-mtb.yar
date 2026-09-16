rule Trojan_Win32_VBInject_BS_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 16 33 c9 8b 42 0c 8b 95 48 ff ff ff 8a 0c 10 8b 45 d8 25 ff 00 00 00 8b d7 33 c8 81 e2 ff 00 00 00 33 ca ff 15 ?? ?? ?? ?? 8b 0e 8b 51 0c 88 04 1a 8b 45 dc 8b 5d e0 03 c7 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}