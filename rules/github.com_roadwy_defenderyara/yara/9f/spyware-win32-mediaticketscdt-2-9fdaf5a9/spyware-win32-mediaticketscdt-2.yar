rule Spyware_Win32_MediaTicketsCDT_2{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 66 2e 6f 75 74 65 72 69 6e 66 6f 2e 63 6f 6d 2f 6e 66 34 30 34 2e 70 68 70 } 		$a_01_1 = {25 73 3f 75 72 6c 3d 25 73 26 72 69 64 3d 25 30 31 30 2e 30 66 } 		$a_01_2 = {7b 32 45 39 44 34 43 38 31 2d 39 46 32 37 2d 34 63 31 34 2d 42 38 30 34 2d 37 42 30 46 36 42 43 38 38 41 34 46 7d } 		$a_01_3 = {6e 64 72 76 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}