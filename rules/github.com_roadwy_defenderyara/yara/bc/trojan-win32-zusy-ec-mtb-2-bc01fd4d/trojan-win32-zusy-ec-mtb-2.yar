rule Trojan_Win32_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b 55 14 80 3a 00 74 f8 90 90 90 90 ac 32 02 aa 90 90 90 90 42 49 85 c9 75 e9 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}