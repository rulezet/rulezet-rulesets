rule Trojan_Win32_Zenpak_M_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 0f b6 3c 0e 01 c7 89 c8 31 db 89 55 d8 89 da 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 8b 7d d8 f7 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}