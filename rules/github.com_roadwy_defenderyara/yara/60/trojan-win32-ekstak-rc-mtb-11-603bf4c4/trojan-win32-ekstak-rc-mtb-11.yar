rule Trojan_Win32_Ekstak_RC_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 00 00 65 00 68 34 30 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 2c 02 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}