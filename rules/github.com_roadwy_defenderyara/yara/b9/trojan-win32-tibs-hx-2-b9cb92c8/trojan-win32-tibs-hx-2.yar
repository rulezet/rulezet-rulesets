rule Trojan_Win32_Tibs_HX_2{
	meta:
		description = "Trojan:Win32/Tibs.HX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 83 e8 03 29 c2 49 eb ?? 89 d7 85 c9 74 02 29 c9 81 c1 90 90 4c 00 00 e8 ?? ff ff ff 59 eb ?? e8 ?? ff ff ff 90 09 08 00 [0-02] c3 51 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}