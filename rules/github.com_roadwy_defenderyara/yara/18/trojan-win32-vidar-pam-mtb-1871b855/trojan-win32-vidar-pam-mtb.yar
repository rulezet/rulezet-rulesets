rule Trojan_Win32_Vidar_PAM_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 95 ?? ?? ?? ?? 32 04 0a 46 88 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}