rule Trojan_Win32_Dridex_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f6 5b fe c5 47 39 f0 89 45 ?? 89 4d ?? 89 55 [0-30] 8b 45 ?? 8b 4d ?? 8a 55 ?? 88 14 01 83 c0 ?? 8b 75 ?? 39 f0 89 45 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}