rule Trojan_Win32_Anobato_A{
	meta:
		description = "Trojan:Win32/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 ff 83 f8 00 74 07 80 7c 03 ff c3 74 06 } 		$a_01_1 = {31 ff c7 43 04 c2 a5 10 28 31 ff 66 c7 43 02 9c 40 31 ff } 		$a_01_2 = {49 89 c7 48 05 00 20 00 00 31 ff 49 89 07 48 05 00 20 00 00 31 ff } 		$a_03_3 = {31 ff 48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 40 01 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff 15 ?? ?? ?? ?? 48 83 c4 20 31 ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}