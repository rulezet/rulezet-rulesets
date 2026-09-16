rule Trojan_Win32_Azorult_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.DA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 02 00 00 00 83 45 f4 03 8b 8d 1c fd ff ff 8b c3 c1 e0 04 89 85 30 fd ff ff 8d 85 30 fd ff ff } 		$a_01_1 = {8b 4d f8 03 cb 8b 85 2c fd ff ff c1 e8 05 89 45 fc } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}