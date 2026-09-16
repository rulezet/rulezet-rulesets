rule Trojan_Win32_RedLine_BS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb } 		$a_00_1 = {50 4f 56 34 68 70 33 48 79 37 74 46 31 72 32 6d } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}