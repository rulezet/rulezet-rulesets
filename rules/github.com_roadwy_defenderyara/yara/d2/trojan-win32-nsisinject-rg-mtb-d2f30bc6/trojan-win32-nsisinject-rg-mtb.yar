rule Trojan_Win32_NSISInject_RG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 53 57 ff 55 f8 [0-20] 8b c1 [0-01] 6a 0c [0-01] 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 39 41 3b cb 72 ea } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}