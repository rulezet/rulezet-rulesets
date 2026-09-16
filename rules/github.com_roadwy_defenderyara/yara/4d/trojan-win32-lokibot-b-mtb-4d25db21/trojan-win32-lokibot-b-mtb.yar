rule Trojan_Win32_Lokibot_B_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f6 8d 84 24 ?? ?? ?? ?? 33 ff 0f 57 c0 50 8d 5f 0a 89 74 24 ?? 89 74 24 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}