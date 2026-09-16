rule Trojan_Win32_Ekstak_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 ff 15 ?? e0 46 00 6a 00 e8 ?? 3b 04 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}