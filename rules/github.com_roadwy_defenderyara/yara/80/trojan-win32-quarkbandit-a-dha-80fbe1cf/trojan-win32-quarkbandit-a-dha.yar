rule Trojan_Win32_QuarkBandit_A_dha{
	meta:
		description = "Trojan:Win32/QuarkBandit.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 06 80 c1 ?? 80 f1 ?? 88 0c 06 46 3b f2 7c ef } 		$a_01_1 = {c7 45 b8 49 6f 63 70 66 c7 45 bc 53 5f } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}