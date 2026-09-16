rule Trojan_Win32_Trickbot_KM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {f6 d2 f6 d1 0a d1 22 d3 83 c4 0c 88 10 40 ff 4d ?? 89 45 ?? 75 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}