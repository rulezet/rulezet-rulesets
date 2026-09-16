rule Trojan_Win32_TrickBot_GM_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 f6 0f 95 c3 [0-10] 85 c0 [0-10] 8a 1a 48 30 19 42 41 4e } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}