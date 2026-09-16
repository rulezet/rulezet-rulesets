rule Trojan_Win32_Valleyrat_AMTB{
	meta:
		description = "Trojan:Win32/Valleyrat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 56 08 8b 45 14 8d 3c 11 8b 55 08 0f b6 04 02 99 bb c8 01 00 00 f7 fb ff 45 08 b8 cd cc cc cc 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}