rule Trojan_Win32_Fareit_VD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 03 d0 80 32 ?? 40 3d ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}