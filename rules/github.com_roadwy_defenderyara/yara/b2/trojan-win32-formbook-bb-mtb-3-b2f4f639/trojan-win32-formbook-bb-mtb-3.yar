rule Trojan_Win32_FormBook_BB_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 08 31 c9 89 45 e8 8b 45 e8 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 } 		$a_01_1 = {83 ec 14 31 c9 39 c1 0f 85 05 00 00 00 e9 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}