rule Trojan_Win32_Ekstak_RC_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 50 ff 15 00 e0 64 00 8b 44 24 0c 8b 4c 24 10 0b c1 5e 83 f0 11 f7 d8 1b c0 40 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}