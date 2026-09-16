rule Trojan_Win32_FormBook_Z_MTB{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 30 50 4f 53 54 74 09 40 } 		$a_01_1 = {04 83 c4 0c 83 06 07 5b 5f 5e 8b e5 5d c3 8b 17 03 55 0c 6a 01 83 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}