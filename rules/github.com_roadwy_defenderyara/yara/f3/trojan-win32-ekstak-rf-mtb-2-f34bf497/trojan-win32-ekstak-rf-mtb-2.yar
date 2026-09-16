rule Trojan_Win32_Ekstak_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 04 b0 65 00 a1 04 15 66 00 50 ff 15 00 b0 65 00 b8 90 01 00 00 8b d0 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}