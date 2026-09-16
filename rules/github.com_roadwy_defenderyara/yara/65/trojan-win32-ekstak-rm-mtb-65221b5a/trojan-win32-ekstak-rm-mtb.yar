rule Trojan_Win32_Ekstak_RM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 10 53 56 57 e8 a2 07 f6 ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}