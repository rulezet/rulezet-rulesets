rule Trojan_Win32_Injuke_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 05 bc 1d 47 00 e8 ?? 8c 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a0 1c 47 00 e8 ?? 48 fe ff 8b 15 a8 1a 47 00 a1 b8 1a 47 00 52 50 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}