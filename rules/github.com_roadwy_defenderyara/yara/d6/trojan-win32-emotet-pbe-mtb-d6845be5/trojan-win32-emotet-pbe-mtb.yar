rule Trojan_Win32_Emotet_PBE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 99 bd 2c 4d 00 00 f7 fd a1 ?? ?? ?? ?? 8d 04 42 2b c6 2b c1 03 44 24 ?? 8b 54 24 ?? 03 44 24 ?? 03 44 24 ?? 03 c7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}