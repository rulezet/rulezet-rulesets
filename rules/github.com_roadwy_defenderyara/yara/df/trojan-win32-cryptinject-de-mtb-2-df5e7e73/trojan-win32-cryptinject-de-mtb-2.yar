rule Trojan_Win32_CryptInject_DE_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.DE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 8b f8 32 40 00 8a c1 0a cc 22 c4 f6 d0 22 c1 43 8a e0 88 24 3e 83 fb 04 72 e5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}