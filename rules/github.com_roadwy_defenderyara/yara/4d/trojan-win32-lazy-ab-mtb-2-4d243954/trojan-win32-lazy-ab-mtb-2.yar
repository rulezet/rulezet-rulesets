rule Trojan_Win32_Lazy_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 ce 89 f0 c1 e0 ?? 01 f0 89 c1 c1 e9 ?? 31 c1 0f b7 44 5a ?? 43 66 85 c0 75 } 		$a_03_1 = {1f 40 00 83 cb ?? 0f b6 db 69 f6 ?? ?? ?? ?? 01 de 0f b7 5c 4f ?? 41 66 85 db 75 } 		$a_03_2 = {01 00 00 0f b6 5c 02 ?? 88 9c 04 ?? 01 00 00 0f b6 54 02 ?? 88 94 04 ?? 01 00 00 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*30+(#a_03_2  & 1)*20) >=50
 
}