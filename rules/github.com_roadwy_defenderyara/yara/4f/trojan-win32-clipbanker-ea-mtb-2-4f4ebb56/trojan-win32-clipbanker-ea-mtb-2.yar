rule Trojan_Win32_ClipBanker_EA_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.EA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 6f 66 31 44 4d c4 41 83 f9 1d 72 f2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}