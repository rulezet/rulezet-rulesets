rule Trojan_Win32_Razy_PGR_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 bb e0 2c 8d 15 ?? ?? ?? ?? 87 cb c1 db 0a 89 d7 ?? 33 f7 c1 e3 0d 33 d8 81 f2 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}