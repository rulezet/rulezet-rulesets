rule Trojan_Win32_Ekstak_RD_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 57 68 98 ?? 54 00 68 48 ?? 54 00 e8 cb ?? fa ff b9 41 00 00 00 33 c0 bf 50 ?? 54 00 f3 ab e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}