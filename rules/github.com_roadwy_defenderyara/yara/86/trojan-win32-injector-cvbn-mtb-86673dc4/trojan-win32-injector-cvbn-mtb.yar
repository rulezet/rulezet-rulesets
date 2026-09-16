rule Trojan_Win32_Injector_CVBN_MTB{
	meta:
		description = "Trojan:Win32/Injector.CVBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 bf 04 00 00 00 99 f7 ff 8b 7d e0 8a 04 17 30 04 0b 41 39 f1 7c e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}