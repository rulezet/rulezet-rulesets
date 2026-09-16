rule Trojan_Win32_Glupteba_AV_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 10 8b 44 24 14 33 d7 33 c2 2b f0 81 c5 47 86 c8 61 83 ac 24 ac 02 00 00 01 0f 85 a7 e6 ff ff 8b 84 24 f8 06 00 00 5f 89 30 5e 5d 89 58 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}