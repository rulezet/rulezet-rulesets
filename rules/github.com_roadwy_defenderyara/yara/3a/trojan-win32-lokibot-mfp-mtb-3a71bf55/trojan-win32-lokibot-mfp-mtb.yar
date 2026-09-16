rule Trojan_Win32_Lokibot_MFP_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {ff 75 08 ff 75 fc 58 59 90 01 c8 ff 30 90 90 59 90 91 34 c5 90 88 01 ff 45 fc 81 7d fc 78 5b 00 00 75 } 		$a_81_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } 		$a_81_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 		$a_81_3 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}