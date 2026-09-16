rule Trojan_Win64_Dridex_QW_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 d0 8a 08 8b 55 94 89 55 fc 48 8b 45 c0 49 89 c0 49 83 c0 01 4c 89 45 c0 44 8b 4d 98 41 81 c1 5e 0b 00 00 44 89 4d fc 88 08 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}