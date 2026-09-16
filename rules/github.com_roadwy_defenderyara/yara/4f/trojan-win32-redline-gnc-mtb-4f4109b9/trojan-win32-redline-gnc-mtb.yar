rule Trojan_Win32_Redline_GNC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 50 e8 ?? ?? ?? ?? 83 c4 04 80 34 1f ?? 43 39 de 0f 85 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}