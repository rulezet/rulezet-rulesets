rule Trojan_Win32_Coroxy_DA_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 89 18 8b 45 cc 03 45 ac 2d ?? ?? ?? ?? 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}