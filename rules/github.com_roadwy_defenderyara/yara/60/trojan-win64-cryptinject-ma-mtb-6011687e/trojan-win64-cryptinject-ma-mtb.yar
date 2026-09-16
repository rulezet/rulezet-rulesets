rule Trojan_Win64_CryptInject_MA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 45 03 c7 99 f7 f9 48 63 c2 42 8a 04 10 41 30 01 4d 03 cf 41 83 f8 02 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}