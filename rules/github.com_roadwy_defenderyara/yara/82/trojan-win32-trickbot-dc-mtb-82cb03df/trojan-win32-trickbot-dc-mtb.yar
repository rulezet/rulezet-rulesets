rule Trojan_Win32_TrickBot_DC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 bf ?? ?? ?? ?? f7 f7 8b 7c 24 0c 8a 04 39 8a 54 14 ?? 32 c2 88 04 39 41 81 f9 e0 07 00 00 75 } 		$a_00_1 = {33 d2 5b 8d 0c 07 8b c7 f7 f3 8b 44 24 10 8a 04 02 30 01 47 3b 7c 24 18 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}