rule Trojan_Win32_TrickBot_DA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a d0 0a 44 24 ?? f6 d2 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10 [0-04] 83 6c 24 ?? 01 89 44 24 ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}