rule Trojan_Win32_Trickbot_MX_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 03 83 c4 0c 8a 54 14 ?? 32 c2 88 03 43 4d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}