rule Trojan_Win32_Zbot_DO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 db 75 07 8b 1e 83 ee fc 11 db 11 c9 eb 52 29 c9 83 e8 03 72 11 c1 e0 08 8a 06 46 83 f0 ff 74 75 d1 f8 50 5d eb 0b 01 db 75 07 8b 1e 83 ee fc 11 db 72 cc } 		$a_01_1 = {8a 06 46 88 07 47 01 db 75 07 8b 1e 83 ee fc 11 db 72 ed } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}