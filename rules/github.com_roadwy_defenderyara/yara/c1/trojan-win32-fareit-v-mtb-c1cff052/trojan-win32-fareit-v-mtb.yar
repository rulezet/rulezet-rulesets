rule Trojan_Win32_Fareit_V_MTB{
	meta:
		description = "Trojan:Win32/Fareit.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 03 d0 73 ?? ?? ?? ?? ?? ?? 80 32 98 40 3d ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}