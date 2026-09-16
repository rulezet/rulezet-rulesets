rule Trojan_Win32_CryptInject_PZ_MTB_3{
	meta:
		description = "Trojan:Win32/CryptInject.PZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 10 8b 45 f0 03 45 ec 0f b6 08 33 ca 8b 55 f0 03 55 ec 88 0a eb d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}