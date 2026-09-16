rule Trojan_Win32_Zusy_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 b9 82 00 00 00 bf b0 79 44 01 68 2b 03 00 00 f3 ab e8 0b f6 ff ff 8b 0d e0 a4 65 00 03 c8 83 c4 04 89 0d e0 a4 65 00 e8 65 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}