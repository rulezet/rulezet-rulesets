rule Trojan_Win32_CryptInject_BM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 88 06 00 00 57 85 f6 74 ?? 31 c0 33 03 83 eb fc 83 e8 33 c1 c8 08 29 d0 83 e8 01 8d 10 c1 c2 09 d1 ca 6a 00 8f 07 01 47 00 83 c7 04 83 ee 04 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}