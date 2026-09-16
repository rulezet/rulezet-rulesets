rule Trojan_Win32_Gozi_GT_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 8b 7c 24 ?? 2b fd 8a 04 2f 8d 4a ?? 4e 88 45 00 8b 15 ?? ?? ?? ?? 03 ce 6b c1 ?? 45 6a db 59 2b c8 03 d1 89 15 ?? ?? ?? ?? 85 f6 75 ?? 5f a1 ?? ?? ?? ?? 83 c0 ?? 50 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}