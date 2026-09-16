rule Trojan_Win32_CryptInject_BU_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d f8 03 de 8a 01 88 45 f5 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f5 32 45 f6 88 03 8a 03 32 45 f7 88 03 eb 05 8a 45 f5 88 03 46 41 4f 75 ca } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}