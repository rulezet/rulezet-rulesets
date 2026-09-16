rule Trojan_Win32_Ekstak_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c2 d1 f8 03 c1 8b 4d f0 89 86 c4 00 00 00 8b 45 f8 2b c1 2b 45 dc 99 2b c2 d1 f8 03 c1 89 86 c8 00 cc cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}