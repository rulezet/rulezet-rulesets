rule Trojan_Win32_NSISInject_RE_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 80 00 00 6a 32 89 44 24 ?? ff d6 50 6a 31 ff d6 50 33 f6 46 56 57 } 		$a_03_1 = {50 c7 45 a8 58 00 00 00 c7 45 b4 ?? ?? ?? ?? c7 45 dc 66 08 88 00 c7 45 ec ?? ?? ?? ?? c7 45 f0 ?? 01 00 00 c7 45 e4 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}