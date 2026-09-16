rule Trojan_Win32_Raccrypt_GR_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 [0-05] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-05] 81 [0-02] 47 86 c8 61 ff [0-05] 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}