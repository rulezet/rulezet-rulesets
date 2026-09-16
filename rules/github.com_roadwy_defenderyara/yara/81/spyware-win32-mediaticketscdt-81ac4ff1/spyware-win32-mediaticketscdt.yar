rule Spyware_Win32_MediaTicketsCDT{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 55 20 53 74 6f 72 65 20 56 61 6c 75 65 } 		$a_01_1 = {72 65 6d 6f 74 65 5f 75 70 64 61 74 65 } 		$a_01_2 = {73 65 65 64 72 65 6d 6f 74 65 5f 75 70 64 61 74 65 } 		$a_01_3 = {43 6c 69 63 6b 73 70 72 69 6e 67 20 41 75 74 6f 72 75 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}