rule Trojan_Win32_Emotet_CM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c8 2b 4d f0 2b 4d ec 8b 75 d0 0f af 75 f0 03 4d cc 03 f1 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}