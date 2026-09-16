rule Trojan_Win32_Ekstak_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 ff 15 b4 b4 64 00 8b d8 a1 24 fc 64 00 3b c7 75 7f 39 3d 28 fc 64 00 75 77 68 03 80 00 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}