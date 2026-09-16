rule Trojan_Win32_Vundo_QA{
	meta:
		description = "Trojan:Win32/Vundo.QA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 30 0c 3e } 		$a_01_1 = {fa 31 e8 67 4d ad 67 83 d8 69 ed df f2 65 fb 7b ea a1 af 57 aa 1d 0b 73 41 d9 91 cf } 		$a_01_2 = {88 cb 6e 71 bf a7 09 ed 2a c3 ab a9 80 1f a5 a5 b8 bb a9 e1 78 97 25 5d 53 b3 d7 19 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}