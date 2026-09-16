rule Ransom_Win32_Gandcrab_G_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 8b 38 8a 44 0f 03 8a d8 80 e3 ?? c0 e3 04 0a 5c 0f 01 88 5d ff 8a d8 24 ?? c0 e0 02 0a 04 0f c0 e3 06 0a 5c 0f 02 88 04 16 8a 45 ff 46 88 04 16 8b 45 0c 46 88 1c 16 83 c1 04 46 3b 08 72 c3 5f } 		$a_03_1 = {8b 44 24 14 8d ?? ?? e8 ?? ?? ff ff 30 06 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}