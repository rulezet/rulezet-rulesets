rule Trojan_Win32_Iceid_AK_MTB{
	meta:
		description = "Trojan:Win32/Iceid.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 ed 6a 00 5f 74 ?? 8d 58 ?? 0f b7 13 89 54 24 ?? 66 c1 6c 24 1c ?? 0f b7 d2 c7 44 24 ?? 00 10 00 00 66 3b 54 24 ?? 72 ?? 81 e2 ff 0f 00 00 03 51 04 03 10 66 83 7c 24 ?? 03 75 ?? 01 32 47 83 c3 02 3b fd 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}