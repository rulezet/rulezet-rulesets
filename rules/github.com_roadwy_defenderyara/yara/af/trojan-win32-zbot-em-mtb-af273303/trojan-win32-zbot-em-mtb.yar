rule Trojan_Win32_Zbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 bb 92 76 b8 91 78 b6 90 7a b4 8f 7b b1 8d 7d af 8c 7f ac 8b 80 aa 8a 82 a8 88 84 a5 87 85 a3 86 87 a0 85 89 9e 83 8b 9c 82 8c 99 81 8e 97 80 90 94 7e 91 92 7d 93 8f 7c 95 8d 7a 96 8b 79 98 } 		$a_01_1 = {74 00 67 00 75 00 78 00 77 00 69 00 6f 00 6f 00 6e 00 72 00 62 00 67 00 61 00 61 00 6c 00 6f 00 70 00 6b 00 63 00 76 00 6a 00 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}