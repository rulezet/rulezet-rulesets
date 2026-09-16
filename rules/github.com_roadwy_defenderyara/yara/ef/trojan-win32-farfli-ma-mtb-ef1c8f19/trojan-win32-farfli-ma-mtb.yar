rule Trojan_Win32_Farfli_MA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 0c b9 fe 00 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 0c 80 c2 08 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } 		$a_00_1 = {8a 50 01 40 80 fa 22 74 29 84 d2 74 25 0f b6 d2 f6 82 } 		$a_00_2 = {ff 01 85 f6 74 d5 8a 10 88 16 46 eb ce } 		$a_03_3 = {88 84 05 ec ?? ?? ?? 40 3b c6 72 f4 8a 45 ?? c6 85 ec ?? ?? ?? ?? 84 c0 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}