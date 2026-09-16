rule Trojan_Win32_Farfli_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 28 4b c6 44 24 2a 52 c6 44 24 2b 4e c6 44 24 2d 4c c6 44 24 2e 33 c6 44 24 2f 32 c6 44 24 30 2e c6 44 24 31 64 88 44 24 32 88 44 24 33 c6 44 24 34 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}