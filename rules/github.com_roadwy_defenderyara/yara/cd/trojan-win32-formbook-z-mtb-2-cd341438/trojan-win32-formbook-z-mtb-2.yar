rule Trojan_Win32_FormBook_Z_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0a 4e 0f b6 08 8d 44 08 01 75 f6 8d 70 01 0f b6 00 8d 55 } 		$a_01_1 = {1a d2 80 e2 af 80 c2 7e eb 2a 80 fa 2f 75 11 8a d0 80 e2 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}