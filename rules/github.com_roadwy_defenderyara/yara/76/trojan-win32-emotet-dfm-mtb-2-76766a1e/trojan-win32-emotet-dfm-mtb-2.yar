rule Trojan_Win32_Emotet_DFM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {f7 e6 8b c6 2b c2 d1 e8 03 c2 8b 54 24 0c c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 11 30 04 3e } 		$a_81_1 = {62 43 75 4e 55 6b 2a 64 7c 50 51 64 37 6c 23 7c 57 40 31 52 40 63 4b 7b 50 33 6a 40 47 6e 71 41 61 4c } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}