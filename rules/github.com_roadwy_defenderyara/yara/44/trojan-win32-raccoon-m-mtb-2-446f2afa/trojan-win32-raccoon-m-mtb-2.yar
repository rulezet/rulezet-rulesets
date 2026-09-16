rule Trojan_Win32_Raccoon_M_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 24 50 6a 00 ff d6 6a 00 8d 4c 24 64 51 ff d7 8d 54 24 48 52 ff d3 33 c9 33 c0 8d 54 24 1c 52 66 89 44 24 24 66 89 4c 24 26 8b 44 24 24 50 51 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}