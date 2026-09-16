rule Trojan_Win32_Emotet_DGE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DGE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc c1 e8 0d 83 e0 01 89 46 14 8b 45 10 89 46 1c 8b 45 14 89 46 20 8b 45 18 89 46 24 8b 45 1c 89 46 28 8b 45 d8 89 46 30 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}