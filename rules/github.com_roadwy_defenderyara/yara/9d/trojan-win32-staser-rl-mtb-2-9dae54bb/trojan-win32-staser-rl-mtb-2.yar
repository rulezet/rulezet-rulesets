rule Trojan_Win32_Staser_RL_MTB_2{
	meta:
		description = "Trojan:Win32/Staser.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3b 7d 0c a9 00 00 80 00 ff 75 14 e8 ?? 8f 06 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}