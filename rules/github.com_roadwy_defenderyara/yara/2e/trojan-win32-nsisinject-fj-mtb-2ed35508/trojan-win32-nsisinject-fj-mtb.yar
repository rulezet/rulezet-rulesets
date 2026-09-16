rule Trojan_Win32_NSISInject_FJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff } 		$a_01_1 = {68 00 a3 e1 11 68 de 00 00 00 ff 75 f4 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}