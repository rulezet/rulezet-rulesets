rule Trojan_Win32_Lokibot_ST_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.ST!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c7 00 8b 4d fc 03 cf 83 c7 00 8a 10 83 c7 00 83 c7 00 32 55 fa 88 11 83 c7 00 83 c7 00 83 c7 00 83 c7 00 8a 55 fb 30 11 83 c7 00 47 40 4e 75 cf } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}