rule Trojan_Win32_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f2 81 e6 ff 00 00 80 79 ?? 4e 81 ce 00 ff ff ff 46 0f b6 94 b5 fc fb ff ff 8b b5 f4 fb ff ff 30 14 06 40 3b c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}