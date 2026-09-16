rule Trojan_Win32_Glupteba_AV_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d cc 6b 84 00 75 06 81 c1 f5 94 08 00 40 3d 45 74 8d 00 7c eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}