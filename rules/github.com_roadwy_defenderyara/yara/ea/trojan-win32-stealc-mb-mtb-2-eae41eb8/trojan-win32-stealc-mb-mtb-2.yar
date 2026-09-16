rule Trojan_Win32_Stealc_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 1c ff ff ff c1 e8 05 89 45 74 8b 45 74 03 85 14 ff ff ff 8b 95 3c ff ff ff 03 d6 33 c2 33 c1 2b f8 83 3d 6c d2 45 02 0c c7 05 64 d2 45 02 ee 3d ea f4 89 45 74 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}