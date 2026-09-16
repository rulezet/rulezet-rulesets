rule Trojan_Win32_Qakbot_EC_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 34 e4 01 3c e4 50 31 04 e4 58 21 45 fc 6a 00 89 2c e4 29 ed 31 c5 89 e9 5d 89 55 f4 33 55 f4 31 c2 } 		$a_01_1 = {6a 00 89 0c e4 ff 75 fc 59 01 f9 89 4d fc 59 c1 e7 04 49 75 eb } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}