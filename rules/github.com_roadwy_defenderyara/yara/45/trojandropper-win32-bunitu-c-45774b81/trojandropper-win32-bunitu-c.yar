rule TrojanDropper_Win32_Bunitu_C{
	meta:
		description = "TrojanDropper:Win32/Bunitu.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3 } 		$a_03_1 = {33 c9 51 50 ff 15 ?? ?? ?? ?? 33 c9 59 ff e1 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}