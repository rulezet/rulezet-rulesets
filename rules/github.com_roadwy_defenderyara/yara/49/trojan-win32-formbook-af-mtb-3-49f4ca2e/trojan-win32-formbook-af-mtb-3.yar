rule Trojan_Win32_FormBook_AF_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 18 c7 45 fc 00 00 00 00 c7 45 e8 00 00 00 00 6a 04 68 00 30 00 00 68 00 09 3d 00 } 		$a_01_1 = {83 7d 0c 00 74 1a 8b 4d fc c6 01 00 8b 55 fc 83 c2 01 89 55 fc 8b 45 0c 83 e8 01 89 45 0c eb e0 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}