rule Trojan_Win32_GuLoader_MA_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {af df 26 be c0 dd 44 8c 78 b6 d8 f9 54 62 21 } 		$a_01_1 = {c4 29 04 03 00 00 00 00 ff cc 31 00 2b b2 2f de ca ed 8e 79 46 9a ec 92 ce c7 a6 62 c2 c9 cb } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}