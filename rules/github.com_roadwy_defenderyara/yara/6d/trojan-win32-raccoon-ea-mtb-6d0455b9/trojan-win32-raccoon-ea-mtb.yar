rule Trojan_Win32_Raccoon_EA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 75 e4 33 f7 2b de 8b 45 ec 29 45 fc 83 6d f4 01 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}