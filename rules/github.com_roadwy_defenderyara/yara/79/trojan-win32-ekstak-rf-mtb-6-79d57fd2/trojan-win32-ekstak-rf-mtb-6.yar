rule Trojan_Win32_Ekstak_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 56 8b 75 14 56 e8 39 a1 20 00 56 ff 15 68 60 65 00 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}