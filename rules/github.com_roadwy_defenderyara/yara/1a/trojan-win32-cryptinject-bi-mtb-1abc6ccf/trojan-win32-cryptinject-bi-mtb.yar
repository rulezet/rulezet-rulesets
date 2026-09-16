rule Trojan_Win32_CryptInject_BI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 ?? be 6c ?? 28 81 e3 15 2d 0d 0f 81 6d ?? 36 18 c4 05 81 f3 26 ed 5f 56 81 45 ?? 40 b7 cb 5c a1 ?? ?? ?? ?? 8b 5d ?? 33 f2 3d 9b 04 00 00 75 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}