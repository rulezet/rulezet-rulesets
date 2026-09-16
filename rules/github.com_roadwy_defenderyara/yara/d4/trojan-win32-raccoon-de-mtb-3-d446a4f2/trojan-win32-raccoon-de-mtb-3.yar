rule Trojan_Win32_Raccoon_DE_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 04 03 4d dc 89 4d fc 8d 0c 03 c1 e8 05 03 45 d8 89 4d ec 89 45 f8 8b 45 ec 31 45 fc } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}