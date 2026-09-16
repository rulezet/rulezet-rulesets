rule Trojan_Win32_NSISInject_RPY_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 ?? fd ff ff ?? ff 55 d8 89 45 ec 83 7d ec ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}