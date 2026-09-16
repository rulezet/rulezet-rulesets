rule Trojan_Win32_Glupteba_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 1d bb [0-04] 8b d6 c7 45 [0-05] d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 8b c3 aa 49 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}