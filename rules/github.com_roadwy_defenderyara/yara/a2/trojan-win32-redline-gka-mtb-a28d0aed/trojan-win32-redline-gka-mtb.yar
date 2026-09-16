rule Trojan_Win32_Redline_GKA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}