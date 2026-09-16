rule Trojan_Win32_Tibs_JG{
	meta:
		description = "Trojan:Win32/Tibs.JG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {87 d6 5a 28 d2 8a 42 01 34 ?? 3c } 		$a_01_1 = {66 0f 6e 04 24 66 0f 7e c2 89 d7 89 fe 89 cb e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}