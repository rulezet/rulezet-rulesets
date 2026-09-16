rule Trojan_Win32_Convagent_BAF_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 0b c8 88 4d f4 8b 45 88 8b 08 33 4d ac 8b 55 90 89 0a 8b 45 d8 2b 45 ec 03 45 d4 03 45 f4 89 45 e0 8b 4d f8 3b 4d dc 77 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}