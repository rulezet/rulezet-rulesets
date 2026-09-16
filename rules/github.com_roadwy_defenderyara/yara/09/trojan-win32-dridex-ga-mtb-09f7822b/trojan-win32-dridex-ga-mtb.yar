rule Trojan_Win32_Dridex_GA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 66 3b cf 74 ?? 0f b7 10 0f af d6 8a ca 8b f2 2a cb 89 35 ?? ?? ?? ?? 2a 4c 24 ?? 8a d9 0f b7 cd 3b d1 74 ?? 83 c0 02 3d ?? ?? ?? ?? 7c } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}