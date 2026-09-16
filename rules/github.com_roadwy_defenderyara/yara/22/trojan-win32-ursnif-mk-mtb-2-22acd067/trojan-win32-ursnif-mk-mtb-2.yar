rule Trojan_Win32_Ursnif_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 03 d1 8d 8a ?? ?? ?? ?? 2b ce 8b f1 1b c7 8b f8 3b 54 24 14 74 0e 8b 44 24 10 40 89 44 24 10 83 f8 ?? 7c d3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}