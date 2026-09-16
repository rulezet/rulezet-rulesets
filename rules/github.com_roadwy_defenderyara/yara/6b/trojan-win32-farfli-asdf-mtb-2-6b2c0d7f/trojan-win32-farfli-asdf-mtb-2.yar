rule Trojan_Win32_Farfli_ASDF_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 8b f1 0f be 04 07 99 f7 7d 0c 8b 45 08 80 c2 4f 30 14 01 b8 cd cc cc cc f7 e1 41 c1 ea 02 8d 04 92 8d 57 01 33 ff 3b f0 0f 45 fa 3b cb 7c } 		$a_01_1 = {56 47 42 4c 67 74 56 52 66 77 43 74 77 64 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}