rule Trojan_Win32_CryptInject{
	meta:
		description = "Trojan:Win32/CryptInject,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 ?? 8a 10 90 90 80 f2 ?? 88 10 90 90 5d } 		$a_03_1 = {33 c0 89 06 90 90 90 90 8b 06 03 c3 73 ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 90 90 ff 06 81 3e ?? ?? 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}