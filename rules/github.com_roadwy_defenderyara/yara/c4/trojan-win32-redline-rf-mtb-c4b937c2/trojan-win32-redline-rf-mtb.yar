rule Trojan_Win32_Redline_RF_MTB{
	meta:
		description = "Trojan:Win32/Redline.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 33 f1 3b d5 7c df 90 09 0e 00 69 0c 93 ?? ?? ?? ?? 42 69 f6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}