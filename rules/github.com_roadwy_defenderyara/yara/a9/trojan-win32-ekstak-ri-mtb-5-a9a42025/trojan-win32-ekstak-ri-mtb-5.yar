rule Trojan_Win32_Ekstak_RI_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 4d f8 51 50 ff 15 90 31 65 00 85 c0 74 0e 8b 45 14 8d 55 fc 52 50 ff 15 c4 30 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}