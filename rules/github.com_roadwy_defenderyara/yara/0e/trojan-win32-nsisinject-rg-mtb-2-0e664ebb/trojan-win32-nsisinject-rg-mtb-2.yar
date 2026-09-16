rule Trojan_Win32_NSISInject_RG_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 56 6a 00 ff d7 53 6a 01 8b f8 56 57 e8 [0-20] 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 39 41 3b ce 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}