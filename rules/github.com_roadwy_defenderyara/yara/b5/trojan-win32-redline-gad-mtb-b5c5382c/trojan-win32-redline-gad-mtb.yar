rule Trojan_Win32_Redline_GAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 2f ?? 83 c4 08 6a 00 6a 00 ff d6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 2f ?? 83 c4 08 6a 00 6a 00 ff d6 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}