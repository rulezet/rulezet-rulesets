rule Trojan_Win32_Danabot_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 ?? 89 45 ?? 89 45 ?? 8d 04 33 33 d0 81 3d } 		$a_01_1 = {33 d0 8b cf 89 55 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}