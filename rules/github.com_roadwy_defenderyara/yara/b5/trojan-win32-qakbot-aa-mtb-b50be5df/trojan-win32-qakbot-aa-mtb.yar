rule Trojan_Win32_Qakbot_AA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 89 4d ?? 2b 4d ?? 09 d9 83 e0 00 09 c8 8b 4d ?? 59 aa 49 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}