rule Trojan_Win32_Guloader_SS_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.SS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb a2 3b a3 41 0f 75 f3 66 0f fd f0 66 0f 60 cb 66 0f f5 f9 0f eb e1 66 0f fe c3 0f d8 e1 31 1c 24 0f dc c9 66 0f 69 c6 66 0f 76 c5 0f dd c3 66 0f e5 d5 66 0f db fb 8f 04 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}