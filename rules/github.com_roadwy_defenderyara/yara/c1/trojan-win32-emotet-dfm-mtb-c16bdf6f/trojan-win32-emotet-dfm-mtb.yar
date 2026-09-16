rule Trojan_Win32_Emotet_DFM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 18 8a 54 14 14 32 c2 88 03 } 		$a_81_1 = {6e 77 61 59 32 72 6e 38 35 44 38 59 77 56 63 79 7a 78 46 65 57 4b 50 55 33 4d 38 6c 31 62 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}