rule Trojan_Win32_Zenpak_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 06 83 f2 07 31 d0 e8 1c 00 00 00 4a 83 e8 03 8d 05 ?? ?? ?? ?? 31 28 01 d0 01 d0 89 35 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}