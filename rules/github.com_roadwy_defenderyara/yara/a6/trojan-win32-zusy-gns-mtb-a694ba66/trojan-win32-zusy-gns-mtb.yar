rule Trojan_Win32_Zusy_GNS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f7 89 f0 31 db 83 c7 58 81 2e ?? ?? ?? ?? 83 c6 04 66 ba ?? ?? 39 fe 7c ?? 66 be ?? ?? bb ?? ?? ?? ?? 53 50 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}