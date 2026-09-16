rule TrojanDropper_Win32_Sirefef_A{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 75 fc 6a 40 59 8d bd dc fe ff ff 8d 85 dc fe ff ff f3 a5 50 8d b5 dc fd ff ff e8 ?? ?? ?? ?? 8b 45 fc 6a 40 8b f0 8d bd dc fe ff ff 59 f3 a5 be ff 00 00 00 03 c6 8b 4d f8 0f b6 0c 01 8a 8c 0d dc fe ff ff 88 08 8b ce 4e 48 85 c9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}