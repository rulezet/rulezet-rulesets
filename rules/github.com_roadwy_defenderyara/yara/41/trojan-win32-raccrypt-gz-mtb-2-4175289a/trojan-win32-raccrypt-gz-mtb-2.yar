rule Trojan_Win32_Raccrypt_GZ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {35 b3 5a 22 c7 45 ?? be a4 bb 7e c7 45 ?? 6a f5 d1 22 c7 45 ?? ce 4d 4a 5f c7 45 ?? 6f e9 1a 32 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}