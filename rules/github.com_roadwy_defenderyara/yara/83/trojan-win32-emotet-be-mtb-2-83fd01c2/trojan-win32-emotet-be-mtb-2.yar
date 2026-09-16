rule Trojan_Win32_Emotet_BE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d f8 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 55 f8 03 55 f0 8b 45 f8 03 45 f0 8b 4d fc 8b 75 f4 8a 14 16 88 14 01 8b 45 f8 83 c0 01 89 45 f8 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}