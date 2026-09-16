rule Trojan_Win32_Ekstak_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 ff 15 ?? ?? 65 00 56 e8 ?? ?? 20 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}