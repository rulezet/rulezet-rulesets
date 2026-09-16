rule Trojan_Win32_NSISInject_RPX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c3 31 ed 55 50 ff d6 89 c6 6a 40 68 00 30 00 00 50 55 ff 15 ?? ?? ?? ?? 89 c7 89 e0 55 50 56 57 53 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}