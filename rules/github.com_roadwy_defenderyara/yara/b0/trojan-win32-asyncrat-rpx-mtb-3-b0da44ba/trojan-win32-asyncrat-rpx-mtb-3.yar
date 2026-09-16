rule Trojan_Win32_AsyncRat_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 2b f3 56 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff } 		$a_01_1 = {31 33 34 2e 31 32 32 2e 31 33 33 2e 34 39 } 		$a_01_2 = {43 6c 69 65 6e 74 2e 62 69 6e } 		$a_01_3 = {47 61 72 62 61 67 65 31 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}