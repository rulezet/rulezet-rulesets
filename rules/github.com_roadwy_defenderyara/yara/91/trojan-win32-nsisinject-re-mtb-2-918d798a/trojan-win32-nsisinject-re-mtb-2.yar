rule Trojan_Win32_NSISInject_RE_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 84 01 ?? ?? ?? ?? 30 44 0e 01 83 c1 02 39 cb 75 d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}