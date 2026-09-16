rule Trojan_Win32_Qakbot_AC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 3a c0 74 ?? 83 f8 46 7e ?? 83 65 fc 00 eb ?? 3a ed 74 ?? 83 f8 41 7c ?? 0f be 45 08 eb ?? c3 } 		$a_03_1 = {51 0f be 45 ?? 66 3b e4 74 ?? 83 f8 30 7c ?? 0f be 45 ?? 66 3b c0 74 ?? 83 f8 66 7e ?? 0f be 45 ?? eb ?? 83 f8 61 7c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}