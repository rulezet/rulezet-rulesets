rule Trojan_Win32_Emotet_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b f3 7e ?? 8b 4d ?? 8d 4c 31 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c6 7c } 		$a_02_1 = {52 53 6a 01 53 50 ff 15 ?? ?? ?? ?? 85 c0 0f 95 c0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}