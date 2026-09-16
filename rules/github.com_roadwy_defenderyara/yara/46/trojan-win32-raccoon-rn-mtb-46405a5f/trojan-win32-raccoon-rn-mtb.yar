rule Trojan_Win32_Raccoon_RN_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 34 af 03 f0 45 53 51 b9 4d 6f 61 64 83 e9 02 8b d9 59 83 c3 01 39 1e 5b 75 e5 53 60 0a ed 66 83 d8 2a 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}