rule Trojan_Win32_Dridex_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 23 00 cc cc [0-01] cc } 		$a_02_1 = {29 df 89 fb 88 dc 88 64 24 ?? 8b 7d ?? 8b 5d ?? 8a 64 24 ?? 88 24 3b 66 8b 7c 24 ?? 66 89 7c 24 ?? 88 44 24 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5) >=10
 
}