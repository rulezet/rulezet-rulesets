rule Adware_Win32_Hebogo{
	meta:
		description = "Adware:Win32/Hebogo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 00 65 00 62 00 6f 00 67 00 6f 00 2e 00 63 00 6f 00 } 		$a_03_1 = {44 00 3a 00 5c 00 74 d5 f4 bc e0 ac 04 d5 5c b8 f8 ad a8 b7 5c 00 53 00 75 00 70 00 65 00 72 00 50 00 6f 00 70 00 75 00 70 00 28 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 [0-06] 43 00 6f 00 6e 00 5c 00 [0-40] 2e 00 76 00 62 00 70 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}