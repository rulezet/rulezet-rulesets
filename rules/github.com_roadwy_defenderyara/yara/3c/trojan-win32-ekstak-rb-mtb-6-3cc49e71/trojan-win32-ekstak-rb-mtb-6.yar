rule Trojan_Win32_Ekstak_RB_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 56 57 ff 15 d8 c1 4b 00 68 ?? e0 4b 00 6a 01 6a 00 8b f8 ff 15 dc c1 4b 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}