rule Trojan_Win32_NSISInject_RD_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-35] 83 7d f4 00 0f 84 1d 00 00 00 8b 45 ec c6 00 00 8b 45 ec 83 c0 01 89 45 ec 8b 45 f4 83 c0 ff 89 45 f4 e9 d9 ff ff ff 8b 45 10 31 c9 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}