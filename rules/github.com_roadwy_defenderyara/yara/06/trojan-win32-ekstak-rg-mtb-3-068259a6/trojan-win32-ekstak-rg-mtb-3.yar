rule Trojan_Win32_Ekstak_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 57 e8 25 ff ff ff e8 60 ff ff ff 8b d8 b9 41 00 00 00 33 c0 bf 64 f7 4c 00 f3 ab e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}