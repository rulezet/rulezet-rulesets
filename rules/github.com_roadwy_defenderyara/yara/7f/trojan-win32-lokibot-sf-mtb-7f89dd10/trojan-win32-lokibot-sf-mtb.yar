rule Trojan_Win32_Lokibot_SF_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 5f 5e c3 90 05 10 01 90 80 f2 cd 88 10 90 05 10 01 90 c3 } 		$a_02_1 = {bb 01 00 00 00 90 05 10 01 90 8b c8 03 cb 73 ?? e8 ?? ?? ?? ?? 90 05 10 01 90 c6 01 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}