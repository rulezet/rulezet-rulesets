rule Trojan_Win32_Tofsee_Z_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 65 72 5f 69 64 } 		$a_01_1 = {73 74 61 72 74 5f 73 72 76 } 		$a_01_2 = {6c 69 64 5f 66 69 6c 65 5f 75 70 64 } 		$a_01_3 = {6c 6f 63 61 6c 63 66 67 } 		$a_01_4 = {49 6e 63 6f 72 72 65 63 74 20 72 65 73 70 6f 6e 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}