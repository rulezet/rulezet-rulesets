rule Worm_Win32_Taterf_gen_E{
	meta:
		description = "Worm:Win32/Taterf.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 30 f0 ff ff 8d bc 05 f8 ef ff ff 0f b7 84 05 08 f0 ff ff 8d 77 14 03 c6 89 45 f4 8b 45 10 3b c3 74 05 8b 4e 1c 89 08 ff 76 38 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}