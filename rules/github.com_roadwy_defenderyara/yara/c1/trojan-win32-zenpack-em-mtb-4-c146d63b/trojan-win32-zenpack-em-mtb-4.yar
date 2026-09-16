rule Trojan_Win32_Zenpack_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 0c 89 e1 c7 41 04 8d 0c 00 00 c7 01 18 05 00 00 } 		$a_01_1 = {83 ec 04 88 44 24 1b e9 60 fb ff ff 8d 65 f8 5e 5f 5d c3 40 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}