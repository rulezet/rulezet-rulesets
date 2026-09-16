rule Trojan_Win32_Ekstak_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 10 53 56 57 e8 82 e8 f5 ff 89 45 fc e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}