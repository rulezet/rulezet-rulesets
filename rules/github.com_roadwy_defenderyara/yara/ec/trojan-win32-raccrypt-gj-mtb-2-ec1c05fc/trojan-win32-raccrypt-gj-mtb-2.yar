rule Trojan_Win32_Raccrypt_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 52 c0 5d 8b 45 ?? 83 25 ?? ?? ?? ?? 00 03 c3 50 8b c3 c1 e0 04 03 45 ?? 90 18 33 44 24 04 c2 ?? ?? 81 00 40 36 ef c6 c3 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}