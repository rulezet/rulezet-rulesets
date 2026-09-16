rule Trojan_Win32_Formbook_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 4f 38 00 20 32 0d 0a 00 00 00 00 ff cc 31 00 00 5a 38 a8 dd 00 61 ce 40 8d 46 3d } 		$a_01_1 = {49 00 6e 00 64 00 75 00 73 00 74 00 72 00 69 00 61 00 6c 00 65 00 6e 00 6f 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}