rule Trojan_Win32_Raccoon_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 8b ce c1 e1 04 03 4d e8 8b c6 c1 e8 05 03 45 ec 03 fe 33 cf 33 c8 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}