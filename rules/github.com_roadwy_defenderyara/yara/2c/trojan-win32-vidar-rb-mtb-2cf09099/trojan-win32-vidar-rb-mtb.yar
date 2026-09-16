rule Trojan_Win32_Vidar_RB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 10 75 08 8b 45 88 88 0c 38 eb 0a 8a 00 32 c1 8b 4d 88 88 04 39 ff 75 90 ff 45 94 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}