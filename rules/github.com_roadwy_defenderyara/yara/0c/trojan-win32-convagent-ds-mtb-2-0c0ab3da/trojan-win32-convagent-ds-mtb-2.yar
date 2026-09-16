rule Trojan_Win32_Convagent_DS_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.DS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 56 c4 08 00 01 45 fc 8b 15 24 90 48 00 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}