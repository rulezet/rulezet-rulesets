rule Ransom_Win32_Teerac_I{
	meta:
		description = "Ransom:Win32/Teerac.I,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 ff 24 95 } 		$a_01_1 = {8b 45 08 ff 30 ff d7 } 		$a_01_2 = {8b 4d 08 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d7 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}