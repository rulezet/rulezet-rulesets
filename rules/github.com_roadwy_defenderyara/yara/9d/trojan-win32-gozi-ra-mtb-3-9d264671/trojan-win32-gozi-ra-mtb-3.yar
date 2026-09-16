rule Trojan_Win32_Gozi_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 75 ?? 57 ff 55 ?? 33 c9 8b f0 39 7d ?? 76 1d 8b c1 99 6a 3c 5f f7 ff 8a 82 ?? ?? ?? ?? 8b 55 ?? 32 04 11 88 04 31 41 3b 4d ?? 72 e3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}