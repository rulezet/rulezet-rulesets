rule Trojan_Win32_Lazy_GV_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c2 80 c1 ?? 32 4c 45 ?? 8d 42 01 88 8e ?? ?? ?? ?? 46 0f b7 d0 81 fe } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}