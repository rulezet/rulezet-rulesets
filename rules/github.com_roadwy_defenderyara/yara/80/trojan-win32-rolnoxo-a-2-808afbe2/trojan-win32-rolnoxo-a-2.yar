rule Trojan_Win32_Rolnoxo_A_2{
	meta:
		description = "Trojan:Win32/Rolnoxo.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 e8 0a 89 46 06 8d 45 fc 50 c6 06 55 c7 46 01 8b ec eb 05 c6 46 05 e9 ff 75 fc 6a 0a 56 ff d7 89 35 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}