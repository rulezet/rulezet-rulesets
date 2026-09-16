rule Trojan_Win32_Redline_MF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8d 45 f8 50 56 8d 85 ?? ?? ?? ?? 50 56 56 68 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}