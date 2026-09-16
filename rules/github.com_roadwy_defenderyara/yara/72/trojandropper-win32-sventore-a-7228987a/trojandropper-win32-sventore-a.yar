rule TrojanDropper_Win32_Sventore_A{
	meta:
		description = "TrojanDropper:Win32/Sventore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce 66 33 04 7d ?? ?? ?? ?? 0f b7 c0 50 e8 ?? ?? ?? ?? 47 3b 7c 24 10 7c de } 		$a_01_1 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}