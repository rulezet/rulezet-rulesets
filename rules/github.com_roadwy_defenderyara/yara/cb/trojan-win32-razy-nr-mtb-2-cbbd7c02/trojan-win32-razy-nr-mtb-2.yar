rule Trojan_Win32_Razy_NR_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 96 cc 65 0b 00 83 c7 ?? 8d 5e fc 31 c0 8a 07 47 09 c0 74 22 3c ?? 77 11 01 c3 } 		$a_03_1 = {24 0f c1 e0 ?? 66 8b 07 83 c7 ?? eb e2 8b ae c0 65 0b 00 8d be ?? ?? ?? ?? bb 00 10 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}