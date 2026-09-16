rule Trojan_Win32_Ramnit_gen_A{
	meta:
		description = "Trojan:Win32/Ramnit.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 70 1c 8f 45 f8 ff 70 38 8f 45 f4 8b 45 fc 05 00 00 01 00 } 		$a_01_1 = {73 13 80 3f 0d 75 0e 80 7f 01 0a 75 08 80 3e 0a 75 03 47 eb 19 } 		$a_01_2 = {40 c6 00 5c 40 c6 00 00 6a 00 8f 85 f4 fe ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}