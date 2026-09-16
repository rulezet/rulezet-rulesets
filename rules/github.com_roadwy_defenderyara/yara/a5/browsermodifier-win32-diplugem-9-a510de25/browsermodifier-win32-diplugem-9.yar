rule BrowserModifier_Win32_Diplugem_9{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 18 01 89 d9 89 f9 81 f1 ff ff ff ff 81 e1 ff ff ff ff 89 d6 81 f6 ff ff ff ff 89 fb 21 f3 09 d9 81 f1 ff ff ff ff 89 c6 31 ce 21 c6 } 		$a_13_1 = {44 24 24 0d 90 01 04 21 c3 09 d9 89 f0 35 ff ff ff ff 25 90 01 04 81 f2 90 01 04 21 d6 89 cf 81 f7 ff ff ff ff 81 e7 90 01 04 21 d1 09 f0 09 cf 31 f8 8b 8c 24 a8 00 00 00 8b 94 24 ac 00 00 00 88 04 0a 90 00 01 } 		$a_05_2 = {05 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_13_1  & 1)*1+(#a_05_2  & 1)*16640) >=3
 
}