rule Trojan_Win32_Ekstak_RC_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 ff 15 a8 f0 46 00 56 ff 15 00 f2 46 00 85 c0 74 07 56 ff 15 a4 f0 46 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}