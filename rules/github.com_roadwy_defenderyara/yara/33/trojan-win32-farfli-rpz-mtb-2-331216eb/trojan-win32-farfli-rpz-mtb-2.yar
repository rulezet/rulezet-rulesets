rule Trojan_Win32_Farfli_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c9 76 11 8d 44 24 0c 50 52 51 8b 4f e4 51 ff 15 ?? ?? ?? ?? 8b 13 0f b7 42 06 45 83 c7 28 3b e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}