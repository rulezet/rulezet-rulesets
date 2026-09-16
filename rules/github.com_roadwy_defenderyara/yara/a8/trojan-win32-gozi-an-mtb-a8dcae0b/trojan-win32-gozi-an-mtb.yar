rule Trojan_Win32_Gozi_AN_MTB{
	meta:
		description = "Trojan:Win32/Gozi.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 ac 89 16 8b 55 bc 8b 0a 8b 55 c0 8b 12 0f b6 0c 0a 8b 16 8b 75 c8 8b 36 0f b6 14 16 31 d1 8b 55 bc 8b 32 8b 55 b8 8b 12 88 0c 32 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}