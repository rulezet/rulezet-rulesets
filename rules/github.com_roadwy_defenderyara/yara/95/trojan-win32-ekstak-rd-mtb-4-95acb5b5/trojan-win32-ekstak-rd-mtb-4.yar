rule Trojan_Win32_Ekstak_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 2c ff 15 d8 94 65 00 85 c0 74 14 e8 cf 54 fb ff e8 7a 02 00 00 e8 f5 5b 09 00 e8 00 b5 12 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}