rule Trojan_Win32_Krypter_AB_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 d2 81 c2 ?? ?? ?? ?? 66 c1 c2 ?? 0f b7 d2 8b 0c 85 ?? ?? ?? ?? 03 ca 88 8c 05 ?? ?? ?? ?? 40 0f b6 c0 0f b6 b5 ?? ?? ?? ?? 3b c6 7c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}