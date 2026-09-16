rule Trojan_Win32_Zusy_RJ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 03 4d e4 0f be 11 0f be 45 14 33 d0 88 55 eb 8b 4d e4 83 c1 01 89 4d e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}