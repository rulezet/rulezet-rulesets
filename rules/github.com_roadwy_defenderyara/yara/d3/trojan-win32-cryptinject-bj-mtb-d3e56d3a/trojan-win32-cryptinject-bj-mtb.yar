rule Trojan_Win32_CryptInject_BJ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 fb 70 0a 00 00 75 ?? 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56 56 56 ff 15 ?? ?? ?? ?? 56 8d 85 18 fb ff ff 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d 14 fb ff ff 30 04 39 81 fb 9b 0a 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}