rule Trojan_Win32_TrickBot_HB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.HB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 10 2b f9 53 50 8b 01 33 02 52 8b d0 51 03 cf 51 58 89 10 59 5a 42 42 58 42 42 3b 55 08 72 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}