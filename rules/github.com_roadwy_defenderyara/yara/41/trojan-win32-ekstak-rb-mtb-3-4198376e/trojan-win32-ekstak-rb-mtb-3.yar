rule Trojan_Win32_Ekstak_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 57 e8 84 ff ff ff b9 41 00 00 00 33 c0 bf 30 e6 4c 00 f3 ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}