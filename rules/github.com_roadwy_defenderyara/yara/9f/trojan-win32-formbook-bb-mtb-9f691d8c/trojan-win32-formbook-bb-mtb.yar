rule Trojan_Win32_FormBook_BB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 04 5d 34 f6 fe c0 34 7e 2c 7d 88 04 37 46 3b f3 72 } 		$a_01_1 = {6a 40 68 00 30 00 00 68 00 09 3d 00 33 f6 56 ff d7 85 c0 75 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}