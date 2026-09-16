rule Trojan_Win32_CryptInject_K_2{
	meta:
		description = "Trojan:Win32/CryptInject.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c6 45 c4 66 c6 85 2f ff ff ff 6c c6 85 89 fe ff ff c5 c6 85 bc fc ff ff c1 c6 85 95 fa ff ff a4 c6 85 bd f8 ff ff 52 c6 85 1b f8 ff ff 0e c6 85 7f f7 ff ff 32 c6 85 89 f5 ff ff d3 c6 85 bd f4 ff ff 33 } 		$a_01_1 = {c6 85 8d fd ff ff 38 c6 85 47 fd ff ff 85 c6 85 fb fa ff ff d4 c6 85 07 fa ff ff 74 c6 85 ee f8 ff ff 7f c6 85 8f f7 ff ff 08 c6 85 be f6 ff ff 5e c6 85 69 f6 ff ff fb c6 85 f2 f3 ff ff 56 c6 85 1b f3 ff ff 89 c6 85 b3 f2 ff ff 0e c6 85 30 f1 ff ff 16 c6 85 41 ef ff ff 9b c6 85 bc ee ff ff 82 c6 85 41 ee ff ff a9 c6 85 21 ee ff ff 98 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}