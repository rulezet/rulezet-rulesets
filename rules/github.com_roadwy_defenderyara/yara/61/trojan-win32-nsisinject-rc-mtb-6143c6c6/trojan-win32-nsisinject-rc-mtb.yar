rule Trojan_Win32_NSISInject_RC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-95] c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 1c 89 85 48 fe ff ff 8b 85 48 fe ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}