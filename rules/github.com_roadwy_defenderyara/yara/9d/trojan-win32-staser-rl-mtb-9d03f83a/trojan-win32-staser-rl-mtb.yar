rule Trojan_Win32_Staser_RL_MTB{
	meta:
		description = "Trojan:Win32/Staser.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 ff 15 34 66 65 00 6a 00 6a 00 ff 15 0c 63 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}