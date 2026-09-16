rule Trojan_Win32_Dridex_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b6 73 28 ce c6 06 56 [0-28] 72 8a 5c 24 ?? 88 9c 24 ?? ?? ?? ?? c6 44 24 ?? 74 b7 9e 28 cf c6 44 24 ?? 75 88 6c 24 ?? c6 44 24 ?? 6c c6 84 24 ?? ?? ?? ?? 4a 88 74 24 73 88 cd 80 f5 5e } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}