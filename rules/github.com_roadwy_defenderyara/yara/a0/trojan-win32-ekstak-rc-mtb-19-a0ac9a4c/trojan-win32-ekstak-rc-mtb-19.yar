rule Trojan_Win32_Ekstak_RC_MTB_19{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 6a 00 ff 15 ?? 67 65 00 56 e8 ?? ?? 20 00 e9 } 		$a_01_1 = {53 00 68 00 72 00 65 00 64 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}