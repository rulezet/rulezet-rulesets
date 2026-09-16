rule Trojan_Win32_Zenpak_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 83 f2 08 01 35 ?? ?? ?? ?? 01 d0 b8 09 00 00 00 48 ba 06 00 00 00 89 f8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 28 b9 02 00 00 00 e2 bf } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}