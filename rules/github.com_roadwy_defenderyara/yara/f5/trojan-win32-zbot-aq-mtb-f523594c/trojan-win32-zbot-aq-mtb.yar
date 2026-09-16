rule Trojan_Win32_Zbot_AQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 db 8a da 80 f3 08 80 38 00 74 06 38 18 74 02 30 18 40 42 3b 15 [0-04] 76 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}