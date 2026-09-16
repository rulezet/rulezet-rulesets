rule Trojan_Win32_Ekstak_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 10 53 56 57 8b 45 08 50 e8 ?? e8 f5 ff 83 c4 04 25 ff ff 00 00 89 45 fc e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}