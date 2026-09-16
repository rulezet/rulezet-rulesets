rule Trojan_Win32_Azorult_RW_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 cb 8d 04 37 89 4c 24 ?? 8b d6 50 8d 4c 24 ?? c1 ea 05 51 c7 [0-05] b4 21 e1 c5 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}