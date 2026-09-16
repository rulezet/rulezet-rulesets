rule Trojan_Win32_NSISInject_RA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 9d b8 f4 ff ff 0f af 9d 0c f5 ff ff 8b 45 14 8b 08 03 8d 18 f5 ff ff 0f be 71 04 03 de 0f be 95 10 f5 ff ff 2b da 89 9d b8 f4 ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}