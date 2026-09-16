rule MonitoringTool_AndroidOS_PhoneSpy_I_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 83 d7 02 6e 20 f1 04 36 00 0a 03 38 03 08 00 52 63 37 01 b1 a3 01 24 01 45 28 06 52 63 37 01 01 34 01 93 01 a5 52 8b d7 02 13 10 00 00 33 ab 1e 00 54 6b 39 01 6e 10 63 08 0b 00 0a 0b 14 0c ff ff ff 7f 32 43 2c 00 } 		$a_01_1 = {52 62 3c 01 52 63 eb 00 52 04 56 00 12 05 71 55 60 04 32 45 0a 02 6e 55 ed 04 f6 21 52 81 d7 02 33 a1 0e 00 6e 20 b5 04 e9 00 0a 01 54 62 39 01 6e 20 5b 08 f2 00 0a 02 b0 12 28 0d 6e 20 b8 04 e9 00 0a 02 54 61 39 01 6e 20 5b 08 f1 00 0a 01 91 01 02 01 52 83 d7 02 54 00 10 01 33 a3 06 00 6e 20 af 04 f0 00 28 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}