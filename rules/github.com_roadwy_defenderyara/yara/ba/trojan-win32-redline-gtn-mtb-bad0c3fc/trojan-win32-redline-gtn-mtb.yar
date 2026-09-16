rule Trojan_Win32_Redline_GTN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 15 ?? ?? ?? ?? 80 34 11 55 8d 04 11 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 4d ?? 3b 0d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}