rule Trojan_Win32_CryptInject_BS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 [0-03] 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 ?? 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 72 90 0a 40 00 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}