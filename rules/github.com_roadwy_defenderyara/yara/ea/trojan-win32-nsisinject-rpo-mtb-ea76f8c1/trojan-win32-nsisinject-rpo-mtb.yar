rule Trojan_Win32_NSISInject_RPO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f0 38 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ac 00 00 00 88 55 ff 0f b6 45 ff f7 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}