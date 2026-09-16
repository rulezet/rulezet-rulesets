rule Trojan_Win32_Ekstak_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c 8d 45 88 50 8d 85 88 fa ff ff ff d0 59 5f 5e 5b c9 c3 55 8b ec 56 e8 8c 63 e4 ff a3 70 6d 85 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}