rule Trojan_Win32_NSISInject_EW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 eb 12 00 00 56 ff 15 } 		$a_03_1 = {88 04 33 46 81 fe eb 12 00 00 72 ?? 6a 00 53 6a 00 ff 15 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}