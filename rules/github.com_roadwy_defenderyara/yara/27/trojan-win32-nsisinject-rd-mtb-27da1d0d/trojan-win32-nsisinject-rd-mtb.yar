rule Trojan_Win32_NSISInject_RD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0e 41 3b cf 72 dd } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}