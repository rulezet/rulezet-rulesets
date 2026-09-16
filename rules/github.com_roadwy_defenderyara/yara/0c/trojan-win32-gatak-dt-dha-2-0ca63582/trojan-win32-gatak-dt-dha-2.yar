rule Trojan_Win32_Gatak_DT_dha_2{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f0 31 c6 45 f1 32 c6 45 f2 33 c6 45 f3 34 c6 45 f4 35 c6 45 f5 35 c6 45 f6 34 c6 45 f7 33 c6 45 f8 32 c6 45 f9 31 88 5d fa ff 15 ?? ?? ?? ?? 66 85 c0 } 	condition:
		((#a_03_0  & 1)*5) >=100
 
}