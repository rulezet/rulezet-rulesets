rule Trojan_Win32_Zenpak_H_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 28 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? 01 18 8d 05 ?? ?? ?? ?? 31 38 e9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}