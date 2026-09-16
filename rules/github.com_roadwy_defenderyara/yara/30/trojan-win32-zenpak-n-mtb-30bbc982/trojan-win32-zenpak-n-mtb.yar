rule Trojan_Win32_Zenpak_N_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d e8 0f b6 3c 0f 01 df 8b 5d ec 0f b6 14 13 01 d7 89 3d 98 78 0d 10 89 f8 99 8b 7d d4 f7 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}