rule Trojan_Win32_Raccoon_RH_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 44 24 7c 8e ac 58 26 81 44 24 60 66 92 e6 2b 81 44 24 30 e5 ae fc 48 8a 9c 02 3b 2d 0b 00 88 1c 30 40 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}