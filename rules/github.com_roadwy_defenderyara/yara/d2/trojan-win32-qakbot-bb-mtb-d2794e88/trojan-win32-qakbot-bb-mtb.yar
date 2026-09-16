rule Trojan_Win32_QakBot_BB_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 5d a0 6a 00 e8 [0-04] 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}