rule Trojan_Win32_Qakbot_GP_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec a1 [0-04] a3 [0-04] 8b [0-06] 89 [0-06] 8b [0-06] 8b 02 a3 [0-04] 8b [0-06] 81 [0-06] 89 [0-06] 8b [0-06] 81 [0-06] a1 [0-04] a3 [0-04] 31 0d [0-04] a1 [0-04] c7 05 [0-08] 01 [0-05] 8b 15 [0-04] a1 [0-04] 89 02 5d c3 } 		$a_02_1 = {88 0a 8b 55 ?? 83 c2 ?? 89 55 ?? e9 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}