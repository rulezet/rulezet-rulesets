rule Trojan_Win32_Ekstak_RL_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 00 8b c8 33 d2 81 e1 ff 00 00 00 8a d4 83 f9 05 8b c2 75 10 83 f8 01 73 18 c7 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}