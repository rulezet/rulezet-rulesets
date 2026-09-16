rule Trojan_Win32_NSISInject_DH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 8d ff fb ff ff 0f b6 b5 ff fb ff ff c1 fe ?? 0f b6 bd ff fb ff ff c1 e7 ?? 89 f1 09 f9 88 8d ff fb ff ff [0-07] 0f b6 b5 ff fb ff ff 89 } 		$a_81_1 = {49 63 6f 4c 65 51 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}