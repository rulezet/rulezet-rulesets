rule Trojan_Win32_Gozi_RC_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 d1 8b c8 81 f1 ?? ?? ?? ?? 57 8b 3d ?? ?? ?? ?? 8b 0c 39 03 cf 0f b7 59 ?? 0f b7 71 ?? 43 6b db 28 03 f1 8b ce 8b f0 81 f6 ?? ?? ?? ?? 03 cb 03 f1 35 ?? ?? ?? ?? 89 55 ?? 89 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}