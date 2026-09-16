rule Trojan_Win32_Injector_ARA_MTB{
	meta:
		description = "Trojan:Win32/Injector.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c7 99 f7 7d 10 8b 45 0c 47 3b fe 8a 04 02 88 84 3d ff fe ff ff 7c e8 } 		$a_01_1 = {8b 45 0c 8a 19 0f b6 14 08 0f b6 c3 03 fa 03 c7 8b fe 99 f7 ff 8b 45 08 8b fa 8a 14 38 03 c7 88 11 41 ff 4d 10 88 18 75 d7 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}