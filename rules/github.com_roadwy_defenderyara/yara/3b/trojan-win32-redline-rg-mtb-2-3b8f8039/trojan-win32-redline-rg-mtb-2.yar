rule Trojan_Win32_Redline_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b 4d 08 8b c6 83 c4 08 f7 75 10 8a 3c 0e 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 32 c3 02 c7 88 04 0e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}