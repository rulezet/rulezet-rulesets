rule Trojan_Win32_CryptInject_MS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ec 83 c4 ?? 51 53 52 57 ff 75 ?? 58 85 c0 74 ?? 33 db 33 d2 bf ?? ?? ?? ?? b9 01 00 00 00 d1 c0 8a dc 8a e6 d1 cb 8b 4d ?? 4f 75 ?? c1 cb ?? 8b c3 5f 5a 5b 59 c9 c2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}