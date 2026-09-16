rule Trojan_Win32_Emotet_NB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 03 2b 06 35 ff ff ff ff 03 06 89 02 2b 35 ?? ?? ?? ?? 47 8b c7 ff 75 18 8f 45 f4 2b 45 f4 } 		$a_81_1 = {6b 62 64 67 72 2e 64 6c 6c } 		$a_81_2 = {4b 62 64 4c 61 79 65 72 44 65 73 63 72 69 70 74 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}