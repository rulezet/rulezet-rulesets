rule Trojan_Win32_Amadey_AMD_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 b8 0b 00 00 ff d7 ff 35 ?? bc 46 00 ff d6 6a 00 6a 01 6a 02 ff 15 ?? ?? ?? ?? 6a 10 8d 4c 24 14 a3 ?? bc 46 00 51 50 ff 15 } 		$a_01_1 = {6a 00 6a 00 6a 00 6a 01 6a 00 ff 15 b8 12 45 00 89 45 d0 83 7d 1c 10 8d 4d 08 6a 00 0f 43 4d 08 6a 00 6a 03 6a 00 6a 00 6a 50 51 50 ff 15 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}