rule Trojan_Win32_CryptInject_K{
	meta:
		description = "Trojan:Win32/CryptInject.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 33 ff ff ff 23 c6 85 13 ff ff ff 30 c6 85 72 fe ff ff 8b c6 85 6a fd ff ff 6b c6 85 fc fb ff ff 8a c6 85 f8 f9 ff ff 77 c6 85 25 f9 ff ff 80 c6 85 a9 f8 ff ff 59 } 		$a_01_1 = {c6 45 c7 6c c6 85 21 ff ff ff c5 c6 85 54 fd ff ff c1 c6 85 2d fb ff ff a4 c6 85 55 f9 ff ff 52 c6 85 b3 f8 ff ff 0e c6 85 17 f8 ff ff 32 c6 85 21 f6 ff ff d3 c6 85 55 f5 ff ff 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}