rule Trojan_Win32_Ekstak_RC_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 29 ff 15 a4 92 65 00 85 c0 a3 e0 ca 65 00 74 18 56 8b 75 14 68 a8 bb 45 01 56 ff 15 50 90 65 00 56 ff 15 4c 90 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}