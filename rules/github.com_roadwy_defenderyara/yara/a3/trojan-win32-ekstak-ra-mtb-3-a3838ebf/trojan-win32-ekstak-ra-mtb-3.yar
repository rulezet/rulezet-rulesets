rule Trojan_Win32_Ekstak_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 68 ?? 30 65 00 6a 01 6a 00 ff 15 ?? f3 64 00 8b f0 85 f6 74 2a ff 15 ?? f3 64 00 3d b7 00 00 00 75 13 56 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}