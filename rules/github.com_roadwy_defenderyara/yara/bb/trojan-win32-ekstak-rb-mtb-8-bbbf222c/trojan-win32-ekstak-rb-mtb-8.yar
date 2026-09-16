rule Trojan_Win32_Ekstak_RB_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 08 a3 e0 ca 65 00 ff 15 54 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 58 90 65 00 56 ff 15 54 90 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}