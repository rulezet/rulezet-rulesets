rule Trojan_Win32_CryptInject_MS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.MS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 2d 00 10 00 00 89 45 d8 c7 45 fc 00 00 00 00 83 e6 3b 2b f3 86 e9 83 fe 3a 8d bd d4 ff ff ff 03 1f ba 01 00 00 00 66 8b c3 83 f9 0f 33 c0 8b 4d d8 66 8b 01 3b 45 cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}