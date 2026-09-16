rule Trojan_Win32_Injuke_RB_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 05 c4 bd 65 00 e8 ?? 55 17 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a8 bc 65 00 e8 2b 00 00 00 6a 00 6a 01 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}