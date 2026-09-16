rule Trojan_Win32_Redline_GNW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 80 b6 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 46 81 fe } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}