rule Trojan_Win32_Zenpak_GZX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 83 c2 03 89 e8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 29 c2 ba 04 00 00 00 01 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 18 b9 02 00 00 00 e2 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}