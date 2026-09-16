rule Trojan_Win32_Zenpak_L_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c2 42 8d 05 ?? ?? ?? ?? 01 38 83 ea 04 89 d0 48 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}