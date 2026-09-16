rule Trojan_Win32_Ekstak_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 e8 c2 ee f5 ff 89 45 fc e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}