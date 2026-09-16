rule Trojan_Win64_Anobato_A_2{
	meta:
		description = "Trojan:Win64/Anobato.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 08 81 38 55 48 89 e5 74 0c 48 83 fb 00 75 06 31 08 ff c1 eb ea } 		$a_03_1 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 80 02 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff 15 ?? ?? ?? ?? 48 83 c4 20 48 83 f8 00 75 02 eb ce } 		$a_01_2 = {81 fb 04 04 00 00 73 09 48 83 c0 04 83 c3 04 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}