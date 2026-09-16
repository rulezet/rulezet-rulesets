rule Trojan_Win32_Ursnif_MTB_21{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 90 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 90 c1 ca 08 e2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}