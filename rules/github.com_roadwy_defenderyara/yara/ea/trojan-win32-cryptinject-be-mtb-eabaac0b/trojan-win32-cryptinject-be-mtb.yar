rule Trojan_Win32_CryptInject_BE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 ?? be 6c ?? 28 81 e3 15 2d 0d 0f 81 6d ?? 36 18 c4 05 81 f3 26 ed 5f 56 81 45 ?? 40 b7 cb 5c 8b 5d ?? 8b 45 ?? 33 d6 2b 4d ?? 40 2b fa 89 4d ?? 89 45 ?? 3b 45 ?? 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}